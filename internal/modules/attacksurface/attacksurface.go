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

// Requires declares crawled_urls and js_secrets as hard dependencies so the
// attack surface is assembled after their producers ran: reading them
// optionally in the same wave as their producers would make the contents
// nondeterministic run-to-run.
func (m *Module) Requires() []string { return []string{"alive_urls", "crawled_urls", "js_secrets"} }
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
func readFfufJSON(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var output struct {
		Results []struct {
			URL string `json:"url"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid ffuf JSON: %w", err)
	}

	var urls []string
	for _, res := range output.Results {
		if res.URL != "" {
			urls = append(urls, res.URL)
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
func resolveEndpoint(jsURL, endpoint string) string {
	base, err := url.Parse(jsURL)
	if err != nil || base.Hostname() == "" {
		return ""
	}
	ref, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || ref.Path == "" {
		return ""
	}
	if ref.IsAbs() {
		return ref.String()
	}
	if !strings.HasPrefix(endpoint, "/") && !strings.HasPrefix(endpoint, "./") && !strings.HasPrefix(endpoint, "../") {
		return ""
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
