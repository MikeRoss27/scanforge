// Package wpthemes enumerates the themes installed on WordPress hosts. It
// mirrors wpplugins: passive detection from crawled /wp-content/themes/<slug>/
// asset references, mixed mode probes style.css for the passively detected
// slugs, aggressive mode probes a bundled wordlist of common theme slugs
// (overridable with --wp-wordlist) and reads style.css headers for versions.
package wpthemes

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
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
	outputRel      = wpcore.OutputDir + "/wp-themes.jsonl"
	reportName     = "wp_themes"
	workerCount    = 8
	requestTimeout = 15 * time.Second
	maxBodyBytes   = 256 * 1024
	maxHosts       = 100
	maxProbes      = 10000
)

//go:embed themes-top.txt
var bundledWordlist []byte

type Finding struct {
	URL        string `json:"url"`
	Theme      string `json:"theme"`
	Version    string `json:"version,omitempty"`
	Source     string `json:"source"`
	Detection  string `json:"detection"`
	Confidence string `json:"confidence"`
	Evidence   string `json:"evidence,omitempty"`
}

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return "wpthemes" }
func (m *Module) Description() string {
	return "Enumerates WordPress themes from crawled assets (passive) and style.css headers (mixed/aggressive)"
}
func (m *Module) Requires() []string     { return []string{"wp_fingerprint"} }
func (m *Module) SoftRequires() []string { return []string{"crawled_urls"} }
func (m *Module) Produces() []string     { return []string{reportName} }

var (
	assetPathRe = regexp.MustCompile(`/wp-content/themes/([A-Za-z0-9_-]+)/`)
	verRe       = regexp.MustCompile(`[?&]ver=([0-9][0-9A-Za-z.-]*)`)
	versionRe   = regexp.MustCompile(`(?i)^Version\s*:\s*([0-9][0-9A-Za-z.-]*)`)
	slugRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,49}$`)
)

type themeKey struct {
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
		runCtx.EmitWarning("wpthemes: no WordPress hosts identified; skipping")
		if err := writeFindings(runCtx.Run.Path(outputRel), nil); err != nil {
			return nil, err
		}
		return finish(m, runCtx)
	}
	if maxHosts > 0 && len(hosts) > maxHosts {
		hosts = hosts[:maxHosts]
	}

	mode := strings.ToLower(strings.TrimSpace(runCtx.WordPress.DetectionMode))
	switch mode {
	case "", "passive":
		mode = "passive"
	case "mixed", "aggressive":
	default:
		runCtx.EmitWarning(fmt.Sprintf("wpthemes: unknown --wp-detection-mode %q; falling back to passive", mode))
		mode = "passive"
	}

	found := map[themeKey]*Finding{}
	addHit := func(host, slug, version, source, detection, evidence string) {
		key := themeKey{host, strings.ToLower(slug)}
		if existing, ok := found[key]; ok {
			if version != "" && existing.Version == "" {
				existing.Version = version
			}
			if source == "style.css" {
				existing.Source = source
				existing.Confidence = "high"
				existing.Evidence = evidence
			}
			return
		}
		conf := "low"
		switch {
		case version != "" && source == "style.css":
			conf = "high"
		case version != "":
			conf = "medium"
		}
		found[key] = &Finding{
			URL:        host,
			Theme:      strings.ToLower(slug),
			Version:    version,
			Source:     source,
			Detection:  detection,
			Confidence: conf,
			Evidence:   evidence,
		}
	}

	scanCrawledArtifact(runCtx, addHit)
	slugs := slugsToProbe(runCtx, mode, found)

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, runner.Command{
		Name: "wpthemes (native)",
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
			runCtx.EmitWarning(fmt.Sprintf("wpthemes: probe set capped at %d (%d requested)", maxProbes, len(probes)))
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

				css := p.host.Target + "/wp-content/themes/" + p.slug + "/style.css"
				status, body, _, _ := modules.WPBody(ctx, client, css, runCtx.Headers, maxBodyBytes)
				if status != http.StatusOK || len(body) == 0 {
					return
				}
				version := ""
				for _, line := range strings.Split(string(body), "\n") {
					if m := versionRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
						version = strings.TrimSpace(m[1])
						break
					}
				}
				if !strings.Contains(strings.ToLower(string(body)), "theme") && version == "" {
					// A 200 page without the style.css shape is a redirect or soft-404.
					return
				}
				mu.Lock()
				addHit(p.host.Target, p.slug, version, "style.css", "aggressive", css)
				mu.Unlock()
			}(p)
		}
		wg.Wait()
	}

	findings := make([]Finding, 0, len(found))
	for _, item := range found {
		findings = append(findings, *item)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].URL != findings[j].URL {
			return findings[i].URL < findings[j].URL
		}
		return findings[i].Theme < findings[j].Theme
	})

	for _, f := range findings {
		detail := f.Theme
		if f.Version != "" {
			detail += " " + f.Version
		}
		runCtx.EmitFinding(modules.Finding{
			Module:   m.Name(),
			Severity: "info",
			Title:    "WordPress theme",
			Target:   f.URL,
			Detail:   detail,
		})
	}

	if err := writeFindings(runCtx.Run.Path(outputRel), findings); err != nil {
		return nil, err
	}
	return finish(m, runCtx)
}

func slugsToProbe(runCtx *modules.RunContext, mode string, found map[themeKey]*Finding) []string {
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

func loadWordlist(path string, bundled []byte) []string {
	origin := bundled
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			origin = bundled
		} else {
			origin = data
		}
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
	art, ok := runCtx.GetArtifact("crawled_urls")
	if !ok {
		return
	}
	file, err := os.Open(runCtx.Run.Path(art.Path))
	if err != nil {
		runCtx.EmitWarning(fmt.Sprintf("wpthemes: cannot read crawled URLs: %v", err))
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
			addHit(base, slug, version, "asset", "passive", line)
		}
	}
}

func finish(m *Module, runCtx *modules.RunContext) (*modules.Result, error) {
	if err := runCtx.AddArtifact(reportName, modules.Artifact{
		Name: reportName,
		Type: "jsonl",
		Path: outputRel,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish wp_themes: %w", err)
	}
	return &modules.Result{
		Name:   m.Name(),
		Status: "completed",
		OutputFiles: map[string]string{
			reportName: outputRel,
		},
	}, nil
}

func writeFindings(path string, items []Finding) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create WordPress themes directory: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create WordPress themes file: %w", err)
	}
	defer func() { _ = file.Close() }()

	for _, item := range items {
		if err := json.NewEncoder(file).Encode(item); err != nil {
			return fmt.Errorf("failed to write WordPress theme: %w", err)
		}
	}
	return nil
}
