// Package attacksurface consolidates every discovered URL (alive hosts,
// crawled pages, fuzzed paths, JS-discovered endpoints) into a single
// de-duplicated attack surface list that downstream vulnerability scanners
// consume, so detection is not limited to the homepage of each host.
package attacksurface

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

const outputRel = "04_surface/attack-surface.txt"

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return "attacksurface" }
func (m *Module) Description() string {
	return "Consolidates alive hosts, crawled URLs, fuzzed paths and JS-discovered endpoints into one attack surface list for downstream scanners"
}

// Requires declares alive_urls as the hard dependency (it always comes from
// httpx, which every web-facing profile includes).
func (m *Module) Requires() []string { return []string{"alive_urls"} }

// SoftRequires keeps the attack surface deterministic when the optional
// upstream producers are part of the profile (they must finish first, so the
// contents never depend on scheduling), while profiles that omit katana,
// ffuf or jssecrets still run: those sources are read conditionally below.
func (m *Module) SoftRequires() []string {
	return []string{"crawled_urls", "discovered_paths", "js_secrets"}
}

func (m *Module) Produces() []string { return []string{"attack_surface_urls"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, _ runner.Executor) (*modules.Result, error) {
	inputArt, err := runCtx.MustArtifact("alive_urls")
	if err != nil {
		return nil, err
	}
	inputFile := runCtx.Run.Path(inputArt.Path)

	var urls []string
	seen := make(map[string]struct{})

	add := func(values []string) {
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			urls = append(urls, value)
		}
	}

	alive, err := readText(inputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read alive URLs: %w", err)
	}
	add(alive)

	// Optional upstreams: each source may be absent depending on the profile,
	// so missing artifacts are skipped rather than treated as an error.
	if art, ok := runCtx.GetArtifact("crawled_urls"); ok {
		crawled, err := readText(runCtx.Run.Path(art.Path))
		if err != nil {
			return nil, fmt.Errorf("failed to read crawled URLs: %w", err)
		}
		add(crawled)
	}

	if art, ok := runCtx.GetArtifact("discovered_paths"); ok {
		paths, err := readFfufJSON(runCtx.Run.Path(art.Path))
		if err != nil {
			return nil, fmt.Errorf("failed to read discovered paths: %w", err)
		}
		add(paths)
	}

	// js_secrets is a jsonl artifact and never passes the scope filter of
	// text artifacts, so every endpoint resolved from it is re-checked here —
	// an in-scope JS file may reference third-party endpoint literals.
	if art, ok := runCtx.GetArtifact("js_secrets"); ok {
		endpoints, err := readJSEndpoints(runCtx, runCtx.Run.Path(art.Path))
		if err != nil {
			return nil, fmt.Errorf("failed to read JS-discovered endpoints: %w", err)
		}
		add(endpoints)
	}

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, runner.Command{
		Name: "attacksurface (native)",
		Args: []string{
			"-input", inputFile,
			"-urls", fmt.Sprintf("%d", len(urls)),
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	outputFile := runCtx.Run.Path(outputRel)
	if err := writeList(outputFile, urls); err != nil {
		return nil, err
	}

	if err := runCtx.AddArtifact("attack_surface_urls", modules.Artifact{
		Name: "attack_surface_urls",
		Type: "text",
		Path: outputRel,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish attack surface: %w", err)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: "completed",
		OutputFiles: map[string]string{
			"attack_surface_urls": outputRel,
		},
	}, nil
}

// readText returns the trimmed non-empty lines of a text artifact. A missing
// file (dry runs, failed upstream) is an empty list rather than an error.
func readText(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var lines []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

// readFfufJSON extracts the full matched URLs from an ffuf JSON output file.
// ffuf writes a single {"results": [...]} document on completion, but a
// killed or timed-out ffuf leaves a truncated file. A streaming decode keeps
// every record completed before the truncation point, so the module - and
// therefore nuclei, which consumes its output - still gets a usable surface
// instead of dying on the corrupt file.
func readFfufJSON(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = file.Close() }()

	dec := json.NewDecoder(file)

	// Walk to the "results" key. A file that does not parse at all (empty,
	// garbage) yields no URLs rather than an error, matching a quiet ffuf.
	open, err := dec.Token()
	if err != nil {
		return nil, nil
	}
	if delim, ok := open.(json.Delim); !ok || delim != '{' {
		return nil, nil
	}
	var urls []string
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, nil
		}
		if key != "results" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return nil, nil
			}
			continue
		}
		if _, err := dec.Token(); err != nil { // consume '['
			return nil, nil
		}
		for dec.More() {
			var record struct {
				URL string `json:"url"`
			}
			// A truncated record ends the stream; everything decoded before
			// it stays usable.
			if err := dec.Decode(&record); err != nil {
				return urls, nil
			}
			if record.URL != "" {
				urls = append(urls, record.URL)
			}
		}
	}
	return urls, nil
}

// readJSEndpoints resolves the endpoint paths reported by jssecrets against
// the JS file they were found in, yielding absolute URLs. Endpoints resolving
// outside the configured scope are dropped: the attack surface must never
// advertise an out-of-scope target to downstream scanners.
func readJSEndpoints(runCtx *modules.RunContext, path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var urls []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		var record struct {
			URL   string `json:"url"`
			Kind  string `json:"kind"`
			Match string `json:"match"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			continue
		}
		if record.Kind != "endpoint" {
			continue
		}
		if resolved := resolveEndpoint(record.URL, record.Match); resolved != "" && runCtx.IsInScope(resolved) {
			urls = append(urls, resolved)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return urls, nil
}

// resolveEndpoint turns a possibly relative endpoint (e.g. "/api/users") into
// an absolute URL using the JS file it was discovered in as the base.
// Bare relative paths like "api/users" or "v1/login" are now resolved against
// the JS file's directory (modern JS frequently uses them); protocol-relative
// URLs (//cdn.example.com/lib.js) inherit the base scheme.
func resolveEndpoint(jsURL, endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" || strings.Contains(endpoint, " ") {
		return ""
	}
	base, err := url.Parse(jsURL)
	if err != nil || base.Hostname() == "" {
		return ""
	}
	ref, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	if ref.Path == "" && ref.RawQuery == "" && ref.Fragment == "" {
		return ""
	}
	if ref.IsAbs() {
		return ref.String()
	}
	if ref.Host != "" {
		ref.Scheme = base.Scheme
		return ref.String()
	}
	return base.ResolveReference(ref).String()
}

func writeList(path string, urls []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create attack surface directory: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create attack surface file: %w", err)
	}
	defer func() { _ = file.Close() }()

	writer := bufio.NewWriter(file)
	for _, value := range urls {
		if _, err := writer.WriteString(value + "\n"); err != nil {
			return fmt.Errorf("failed to write attack surface file: %w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush attack surface file: %w", err)
	}
	return nil
}
