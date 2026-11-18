// Package wpplugins enumerates the plugins installed on WordPress hosts.
// Passive mode parses the crawled URLs for /wp-content/plugins/<slug>/ asset
// references (the same default-detection signal as wpscan). Mixed mode adds
// readme.txt probes for the slugs found passively. Aggressive mode probes a
// bundled wordlist of well-known plugin slugs (overridable with
// --wp-wordlist) and reads readme.txt for each: this is the closest
// equivalent of `wpscan --enumerate p --plugins-detection aggressive`.
package wpplugins

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/modules/wpcore"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

const (
	outputRel      = wpcore.OutputDir + "/wp-plugins.jsonl"
	fpFile         = wpcore.OutputDir + "/wp-fingerprint.jsonl"
	reportName     = "wp_plugins"
	workerCount    = 8
	requestTimeout = 15 * time.Second
	maxBodyBytes   = 256 * 1024
	maxHosts       = 100
	maxProbes      = 20000
)

//go:embed plugins-top.txt
var bundledWordlist []byte

type Finding struct {
	URL        string `json:"url"`
	Plugin     string `json:"plugin"`
	Version    string `json:"version,omitempty"`
	Source     string `json:"source"`
	Detection  string `json:"detection"`
	Confidence string `json:"confidence"`
	Evidence   string `json:"evidence,omitempty"`
}

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return "wpplugins" }
func (m *Module) Description() string {
	return "Enumerates WordPress plugins from crawled assets (passive) and plugin readme.txt files (mixed/aggressive)"
}
func (m *Module) Requires() []string     { return []string{"wp_fingerprint"} }
func (m *Module) SoftRequires() []string { return []string{"crawled_urls"} }
func (m *Module) Produces() []string     { return []string{reportName} }

var (
	assetPathRe = regexp.MustCompile(`/wp-content/plugins/([A-Za-z0-9_-]+)/`)
	verRe       = regexp.MustCompile(`[?&]ver=([0-9][0-9A-Za-z.-]*)`)
	stableRe    = regexp.MustCompile(`(?i)Stable\s*tag\s*:\s*([0-9][0-9A-Za-z.-]*)`)
	slugRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,49}$`)
)

type pluginKey struct {
	host string
	slug string
}

type probeJob struct {
	host wpcore.FingerprintRecord
	slug string
}

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, _ runner.Executor) (*modules.Result, error) {
	fpArt, err := runCtx.MustArtifact("wp_fingerprint")
	if err != nil {
		return nil, err
	}
	hosts, err := wpcore.LoadFingerprint(runCtx.Run.Path(fpArt.Path))
	if err != nil {
		return nil, fmt.Errorf("failed to read wp_fingerprint: %w", err)
	}
	if len(hosts) == 0 {
		runCtx.EmitWarning("wpplugins: no WordPress hosts identified; skipping")
		if err := writeFindings(runCtx.Run.Path(outputRel), nil); err != nil {
			return nil, err
		}
		return finish(m, runCtx)
	}
	if maxHosts > 0 && len(hosts) > maxHosts {
		hosts = hosts[:maxHosts]
	}

	mode, modeErr := effectiveDetectionMode(runCtx.WordPress.DetectionMode)
	if modeErr != nil {
		runCtx.EmitWarning(fmt.Sprintf("wpplugins: %v; falling back to passive", modeErr))
		mode = "passive"
	}

	found := map[pluginKey]*Finding{}
	addHit := func(host, slug, version, source, detection, evidence string) {
		key := pluginKey{host, strings.ToLower(slug)}
		if existing, ok := found[key]; ok {
			if version != "" && existing.Version == "" {
				existing.Version = version
			}
			if source == "readme" {
				existing.Source = "readme"
				existing.Confidence = "high"
				existing.Evidence = evidence
			}
			return
		}
		found[key] = &Finding{
			URL:        host,
			Plugin:     strings.ToLower(slug),
			Version:    version,
			Source:     source,
			Detection:  detection,
			Confidence: confidenceFor(version, source),
			Evidence:   evidence,
		}
	}

	scanCrawledArtifact(runCtx, addHit)

	slugs := slugsToProbe(runCtx, mode, found)
	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, runner.Command{
		Name: "wpplugins (native)",
		Args: []string{"-mode", mode, "-hosts", fmt.Sprintf("%d", len(hosts)), "-slugs", fmt.Sprintf("%d", len(slugs))},
	}); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	if mode != "passive" && !runCtx.DryRun && len(slugs) > 0 {
		client, closeConn, err := modules.NewProxyClient(runCtx.Proxy, requestTimeout)
		if err != nil {
			return nil, err
		}
		defer closeConn()

		var probes []probeJob
		for _, host := range hosts {
			for _, slug := range slugs {
				probes = append(probes, probeJob{host, slug})
			}
		}
		if len(probes) > maxProbes {
			runCtx.EmitWarning(fmt.Sprintf("wpplugins: probe set capped at %d (%d requested)", maxProbes, len(probes)))
			probes = probes[:maxProbes]
		}

		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, workerCount)
		for _, p := range probes {
			wg.Add(1)
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				wg.Done()
				wg.Wait()
				return nil, ctx.Err()
			}
			go func(p probeJob) {
				defer wg.Done()
				defer func() { <-sem }()

				readme := p.host.Target + "/wp-content/plugins/" + p.slug + "/readme.txt"
				_, body, _, _ := modules.WPBody(ctx, client, readme, runCtx.Headers, maxBodyBytes)
				if body == nil {
					return
				}
				lower := strings.ToLower(string(body))
				if !strings.Contains(lower, "stable tag") && !strings.Contains(lower, "plugin") {
					// A 200 page without any plugin-readme shape is a redirect or soft-404.
					return
				}
				version := ""
				if m := stableRe.FindSubmatch(body); m != nil {
					version = strings.TrimSpace(string(m[1]))
				}
				mu.Lock()
				addHit(p.host.Target, p.slug, version, "readme", "aggressive", readme)
				mu.Unlock()
			}(p)
		}
		wg.Wait()
	}

	findings := make([]Finding, 0, len(found))
	for _, item := range found {
		if item.Evidence == "" {
			item.Evidence = "asset path"
		}
		findings = append(findings, *item)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].URL != findings[j].URL {
			return findings[i].URL < findings[j].URL
		}
		return findings[i].Plugin < findings[j].Plugin
	})

	for _, f := range findings {
		detail := f.Plugin
		if f.Version != "" {
			detail += " " + f.Version
		}
		runCtx.EmitFinding(modules.Finding{
			Module:   m.Name(),
			Severity: "info",
			Title:    "WordPress plugin",
			Target:   f.URL,
			Detail:   detail,
		})
	}

	if err := writeFindings(runCtx.Run.Path(outputRel), findings); err != nil {
		return nil, err
	}
	return finish(m, runCtx)
}

func finish(m *Module, runCtx *modules.RunContext) (*modules.Result, error) {
	if err := runCtx.AddArtifact(reportName, modules.Artifact{
		Name: reportName,
		Type: "jsonl",
		Path: outputRel,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish wp_plugins: %w", err)
	}
	return &modules.Result{
		Name:   m.Name(),
		Status: "completed",
		OutputFiles: map[string]string{
			reportName: outputRel,
		},
	}, nil
}

// effectiveDetectionMode normalizes and validates the configured detection
// mode. Unknown values produce an error so the caller can warn and fall back.
func effectiveDetectionMode(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "passive":
		return "passive", nil
	case "mixed":
		return "mixed", nil
	case "aggressive":
		return "aggressive", nil
	default:
		return "", fmt.Errorf("unknown --wp-detection-mode %q (want passive|mixed|aggressive)", raw)
	}
}

// slugsToProbe returns the slugs worth probing in the configured mode:
// mixed = only the passively detected slugs, aggressive = bundled or
// user-provided wordlist union the passive hits.
func slugsToProbe(runCtx *modules.RunContext, mode string, found map[pluginKey]*Finding) []string {
	if mode == "passive" {
		return nil
	}
	seen := map[string]struct{}{}
	var slugs []string
	if mode == "aggressive" {
		for _, slug := range loadWordlist(runCtx.WordPress.Wordlist, bundledWordlist) {
			if _, dup := seen[slug]; !dup {
				seen[slug] = struct{}{}
				slugs = append(slugs, slug)
			}
		}
	}
	for key := range found {
		if _, dup := seen[key.slug]; !dup {
			seen[key.slug] = struct{}{}
			slugs = append(slugs, key.slug)
		}
	}
	sort.Strings(slugs)
	return slugs
}

// loadWordlist reads a user-provided wordlist or falls back to the bundled
// one. Lines are trimmed, lowercased and validated against the WP slug shape.
func loadWordlist(path string, bundled []byte) []string {
	origin := bundled
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			// Callers surface this via a warning upstream when they want to;
			// keep the bundled list as a sane fallback.
			return loadWordlist("", bundled)
		}
		origin = data
	}
	seen := map[string]struct{}{}
	out := []string{}
	for _, line := range strings.Split(string(origin), "\n") {
		slug := strings.ToLower(strings.TrimSpace(line))
		if !slugRe.MatchString(slug) {
			continue
		}
		if _, dup := seen[slug]; dup {
			continue
		}
		seen[slug] = struct{}{}
		out = append(out, slug)
	}
	return out
}

func scanCrawledArtifact(runCtx *modules.RunContext, addHit func(host, slug, version, source, detection, evidence string)) {
	pathArtifact, ok := runCtx.GetArtifact("crawled_urls")
	if !ok {
		return
	}
	file, err := os.Open(runCtx.Run.Path(pathArtifact.Path))
	if err != nil {
		runCtx.EmitWarning(fmt.Sprintf("wpplugins: cannot read crawled URLs: %v", err))
		return
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		base, ok := modules.WPBaseURL(line)
		if !ok {
			continue
		}
		version := ""
		if vm := verRe.FindStringSubmatch(line); vm != nil {
			version = vm[1]
		}
		matched := map[string]bool{}
		for _, m := range assetPathRe.FindAllStringSubmatch(line, -1) {
			slug := strings.ToLower(m[1])
			if matched[slug] {
				continue
			}
			matched[slug] = true
			addHit(base, slug, version, "asset", "passive", shortenURL(line))
		}
	}
}

func shortenURL(line string) string {
	u, err := url.Parse(line)
	if err != nil {
		return line
	}
	if i := strings.Index(u.Path, "/wp-content/plugins/"); i >= 0 {
		return "…" + u.Path[i:]
	}
	return line
}

func confidenceFor(version, source string) string {
	if source == "readme" {
		return "high"
	}
	if version != "" {
		return "medium"
	}
	return "low"
}

func writeFindings(path string, items []Finding) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create WordPress plugins directory: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create WordPress plugins file: %w", err)
	}
	defer func() { _ = file.Close() }()

	for _, item := range items {
		if err := json.NewEncoder(file).Encode(item); err != nil {
			return fmt.Errorf("failed to write WordPress plugin: %w", err)
		}
	}
	return nil
}
