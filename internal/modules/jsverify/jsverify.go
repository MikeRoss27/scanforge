// Package jsverify replays the PoC payloads attached to jssecrets AST
// findings in a real headless browser, injecting them through the attack
// sources the sink classes rely on (URL parameters, URL fragment, window
// postMessage) and reporting whether the payload actually reached the sink
// or executed JavaScript on the page.
package jsverify

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

const (
	// maxVerify caps how many findings are replayed per run. Each replay
	// costs a full page load plus a settle window, so high-severity findings
	// are prioritized and everything else stays unverified.
	maxVerify = 20
	// outputRel is the verdict log path relative to the run directory.
	outputRel = "06_vulns/js-verified.jsonl"
)

// astKinds are the jssecrets finding kinds produced by static analysis, i.e.
// the only ones that carry replayable PoC payloads.
var astKinds = map[string]struct{}{
	"dom-sink":        {},
	"proto-pollution": {},
	"postmessage":     {},
	"node-sink":       {},
	"env-leak":        {},
}

// finding mirrors the subset of jssecrets findings the verifier needs.
type finding struct {
	URL      string   `json:"url"`
	Kind     string   `json:"kind"`
	Pattern  string   `json:"pattern"`
	Severity string   `json:"severity"`
	Payloads []string `json:"payloads"`
}

// verdict is one replay outcome, written as one JSON line per finding.
type verdict struct {
	URL      string `json:"url"`
	Page     string `json:"page"`
	Kind     string `json:"kind"`
	Pattern  string `json:"pattern"`
	Severity string `json:"severity"`
	Payload  string `json:"payload"`
	// Verdict is one of "executed" (the payload ran JavaScript),
	// "sink-reached" (the payload reached a monitored sink without running),
	// "not-observed" (page loaded but the sink never saw the payload) or
	// "unreachable" (the page could not be loaded at all).
	Verdict  string `json:"verdict"`
	Evidence string `json:"evidence,omitempty"`
}

// Module verifies jssecrets PoC payloads in a headless browser.
type Module struct {
	browserPath string
}

// New returns the module. browserPath is the chromium/chrome executable
// (from tools.chromium); an empty value makes the module auto-detect.
func New(browserPath string) *Module { return &Module{browserPath: browserPath} }

func (m *Module) Name() string { return "jsverify" }
func (m *Module) Description() string {
	return "Replays jssecrets PoC payloads in a headless browser (payload injected via URL parameters, fragment and postMessage) and reports executed, sink-reached, or not-observed verdicts"
}
func (m *Module) Requires() []string { return []string{"js_secrets", "crawled_urls"} }
func (m *Module) Produces() []string { return []string{"js_verified"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, _ runner.Executor) (*modules.Result, error) {
	secretsArt, err := runCtx.MustArtifact("js_secrets")
	if err != nil {
		return nil, err
	}
	crawlArt, err := runCtx.MustArtifact("crawled_urls")
	if err != nil {
		return nil, err
	}

	findings, err := readFindings(runCtx, runCtx.Run.Path(secretsArt.Path))
	if err != nil {
		return nil, fmt.Errorf("failed to read JS secrets findings: %w", err)
	}
	findings = prioritize(findings, maxVerify)

	pages, err := readPages(runCtx.Run.Path(crawlArt.Path))
	if err != nil {
		return nil, fmt.Errorf("failed to read crawled URLs: %w", err)
	}

	browser := m.browserPath
	if browser == "" {
		browser = detectBrowser()
	} else if resolved, err := exec.LookPath(browser); err == nil {
		browser = resolved
	} else if _, err := os.Stat(browser); err != nil {
		// A configured path that does not exist is as good as no browser:
		// report the skip once instead of failing every replay.
		browser = ""
	}

	if browser == "" {
		// Nothing can be launched: the audit trail still records why.
		if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, runner.Command{
			Name: "jsverify (chromedp)",
			Args: []string{
				"-input", secretsArt.Path,
				"-findings", strconv.Itoa(len(findings)),
				"-browser", "unavailable",
			},
		}); err != nil {
			return nil, fmt.Errorf("failed to write commands log: %w", err)
		}
	} else if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, chromiumLaunchCommand(browser, runCtx.Proxy)); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	var results []verdict
	if !runCtx.DryRun && len(findings) > 0 {
		if browser == "" {
			results = []verdict{{
				Kind:     "browser-unavailable",
				Pattern:  "skipped",
				Severity: "info",
				Verdict:  "not-observed",
				Evidence: "no chromium/chrome binary found (set tools.chromium in scanforge.yaml)",
			}}
		} else {
			var launchErr error
			results, launchErr = verifyAll(ctx, runCtx, browser, findings, pages)
			if launchErr != nil {
				// chromedp exits with the browser's OS exit status; the
				// runner never executes it, so trace the failure here.
				if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, runner.Command{
					Name: "jsverify (chromedp)",
					Args: []string{
						"-input", secretsArt.Path,
						"-findings", strconv.Itoa(len(findings)),
						"-status", "failed-to-launch",
						"-error", launchErr.Error(),
					},
				}); err != nil {
					return nil, fmt.Errorf("failed to write commands log: %w", err)
				}
			}
		}
	}

	if err := writeVerdicts(runCtx.Run.Path("06_vulns", "js-verified.jsonl"), results); err != nil {
		return nil, err
	}
	if err := runCtx.AddArtifact("js_verified", modules.Artifact{
		Name: "js_verified",
		Type: "jsonl",
		Path: outputRel,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish JS verification results: %w", err)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: "completed",
		OutputFiles: map[string]string{
			"js_verified": outputRel,
		},
	}, nil
}

// readFindings loads jssecrets findings, keeping only the AST-based kinds
// that carry PoC payloads and dropping anything without one or outside the
// configured scope. Scope is checked again here because js_secrets is a
// jsonl artifact that the text-artifact scope filter does not cover, and an
// out-of-scope finding must never be replayed against a third-party host.
func readFindings(runCtx *modules.RunContext, path string) ([]finding, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var findings []finding
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		var item finding
		if json.Unmarshal(scanner.Bytes(), &item) != nil {
			continue
		}
		if _, ok := astKinds[item.Kind]; !ok || len(item.Payloads) == 0 {
			continue
		}
		parsed, err := url.Parse(item.URL)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			continue
		}
		if !runCtx.IsInScope(item.URL) {
			continue
		}
		findings = append(findings, item)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return findings, nil
}

// severityRank orders severities for prioritization when the verification
// budget runs out.
var severityRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

// prioritize deduplicates findings (same URL + pattern, keeping the first
// occurrence) and returns at most limit of them, highest severity first.
func prioritize(findings []finding, limit int) []finding {
	seen := make(map[string]struct{}, len(findings))
	var kept []finding
	for _, item := range findings {
		key := item.URL + "\x00" + item.Pattern
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		kept = append(kept, item)
	}
	sort.SliceStable(kept, func(i, j int) bool {
		return severityRank[kept[i].Severity] > severityRank[kept[j].Severity]
	})
	if len(kept) > limit {
		kept = kept[:limit]
	}
	return kept
}

// readPages builds a lookup of host origin -> first page URL from the crawl
// output, so each finding can be replayed on a page that actually uses the
// chunk instead of the raw .js URL. Assets and binary-looking paths are
// skipped; the lookup falls back to the origin root.
func readPages(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = file.Close() }()

	pages := make(map[string]string)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || !strings.HasPrefix(raw, "http") {
			continue
		}
		parsed, err := url.Parse(raw)
		if err != nil {
			continue
		}
		if isAssetPath(parsed.Path) {
			continue
		}
		origin := parsed.Scheme + "://" + parsed.Host
		if _, ok := pages[origin]; !ok {
			pages[origin] = raw
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return pages, nil
}

// assetExtensions are crawled paths that can never run the chunk's code.
var assetExtensions = []string{
	".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
	".webp", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip",
	".gz", ".map", ".txt", ".xml", ".json", ".mp4", ".webm", ".mp3",
}

func isAssetPath(path string) bool {
	lower := strings.ToLower(path)
	for _, ext := range assetExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func writeVerdicts(path string, results []verdict) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create JS verification output directory: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create JS verification output: %w", err)
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	for _, item := range results {
		if err := encoder.Encode(item); err != nil {
			return fmt.Errorf("failed to write JS verification output: %w", err)
		}
	}
	return nil
}
