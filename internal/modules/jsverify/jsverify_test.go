package jsverify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
	scanScope "github.com/MikeRoss27/scanforge/internal/scope"
	"github.com/MikeRoss27/scanforge/internal/storage"
	"github.com/chromedp/chromedp"
)

func writeJSONL(t *testing.T, path string, items []interface{}) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create fixture: %v", err)
	}
	defer func() { _ = file.Close() }()
	encoder := json.NewEncoder(file)
	for _, item := range items {
		if err := encoder.Encode(item); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}
}

func findingLine(url, kind, pattern, severity string, payloads []string) map[string]interface{} {
	return map[string]interface{}{
		"url": url, "kind": kind, "pattern": pattern,
		"severity": severity, "payloads": payloads,
	}
}

func TestReadFindingsKeepsOnlyReplayable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "js-secrets.jsonl")
	writeJSONL(t, path, []interface{}{
		findingLine("https://a.example/app.js", "dom-sink", "eval-call", "high", []string{`alert(1)`}),
		findingLine("https://a.example/app.js", "secret", "aws-access-key-id", "critical", []string{`AKIA...`}),
		findingLine("https://a.example/app.js", "dom-sink", "html-assignment", "high", nil),
		findingLine("not a url", "dom-sink", "eval-call", "high", []string{`alert(1)`}),
		"not json at all",
		findingLine("https://a.example/app.js", "postmessage", "postmessage-wildcard", "medium", []string{`parent.postMessage("x","*")`}),
	})

	got, err := readFindings(modules.NewRunContext("a.example", "web", false, nil), path)
	if err != nil {
		t.Fatalf("readFindings: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("findings = %d, want 2 (regex secrets, missing payloads, bad URL and junk dropped): %+v", len(got), got)
	}
	if got[0].Pattern != "eval-call" || got[1].Pattern != "postmessage-wildcard" {
		t.Fatalf("unexpected findings: %+v", got)
	}
}

func TestReadFindingsMissingFile(t *testing.T) {
	got, err := readFindings(modules.NewRunContext("a.example", "web", false, nil), filepath.Join(t.TempDir(), "nope.jsonl"))
	if err != nil || got != nil {
		t.Fatalf("readFindings = %v, %v; want nil, nil", got, err)
	}
}

func TestReadFindingsDropsOutOfScope(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "js-secrets.jsonl")
	writeJSONL(t, path, []interface{}{
		findingLine("https://a.example/app.js", "dom-sink", "eval-call", "high", []string{`alert(1)`}),
		findingLine("https://attacker.example/evil.js", "dom-sink", "eval-call", "high", []string{`alert(1)`}),
	})
	scope, err := scanScope.FromTarget("a.example", scanScope.ModeDomain, nil, nil)
	if err != nil {
		t.Fatalf("build scope: %v", err)
	}
	got, err := readFindings(modules.NewRunContext("a.example", "web", false, nil, scope), path)
	if err != nil {
		t.Fatalf("readFindings: %v", err)
	}
	if len(got) != 1 || got[0].URL != "https://a.example/app.js" {
		t.Fatalf("findings = %+v, want only the in-scope finding", got)
	}
}

func TestPrioritizeDeduplicatesAndCaps(t *testing.T) {
	findings := []finding{
		{URL: "https://a.example/x.js", Pattern: "eval-call", Severity: "low"},
		{URL: "https://a.example/x.js", Pattern: "eval-call", Severity: "high"},
		{URL: "https://a.example/y.js", Pattern: "eval-call", Severity: "high"},
		{URL: "https://a.example/y.js", Pattern: "html-assignment", Severity: "high"},
		{URL: "https://a.example/z.js", Pattern: "proto-pollution-assignment", Severity: "critical"},
	}

	got := prioritize(findings, 3)
	if len(got) != 3 {
		t.Fatalf("prioritize = %d findings, want 3 (dedup + cap): %+v", len(got), got)
	}
	// critical first, then high, and the duplicate pattern collapsed.
	if got[0].Pattern != "proto-pollution-assignment" || got[0].Severity != "critical" {
		t.Fatalf("critical not first: %+v", got[0])
	}
	if got[1].Pattern != "eval-call" || got[1].Severity != "high" {
		t.Fatalf("high not second: %+v", got[1])
	}
}

func TestReadPagesSkipsAssets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "crawled.txt")
	content := strings.Join([]string{
		"https://a.example/",
		"https://a.example/app.js",
		"https://a.example/style.css",
		"https://a.example/logo.png",
		"https://a.example/private/search?x=1",
		"not a url",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	pages, err := readPages(path)
	if err != nil {
		t.Fatalf("readPages: %v", err)
	}
	if len(pages) != 1 {
		t.Fatalf("pages = %v, want only one origin entry", pages)
	}
	if pages["https://a.example"] != "https://a.example/" {
		t.Fatalf("first page should be the root, got %q", pages["https://a.example"])
	}
}

func TestMarkPayload(t *testing.T) {
	cases := map[string]string{
		`alert(document.domain)`:           `alert("__SF__3")`,
		`<img src=x onerror=alert(1)>`:     `<img src=x onerror=alert("__SF__3")>`,
		`{"__proto__": {"isAdmin": true}}`: `{"__proto__": {"isAdmin": true}}`,
		`https://attacker.example/`:        `https://attacker.example/#__SF__3`,
	}
	for payload, want := range cases {
		if got := markPayload(payload, 3); got != want {
			t.Errorf("markPayload(%q) = %q, want %q", payload, got, want)
		}
	}
}

func TestAttackURLsCarryPayload(t *testing.T) {
	variants := attackURLs("https://a.example/page?keep=1", `<img src=x onerror=alert("__SF__1")>`)
	if len(variants) != 2 {
		t.Fatalf("variants = %d, want 2", len(variants))
	}
	if !strings.Contains(variants[0], "q=%3Cimg") || !strings.Contains(variants[0], "keep=1") {
		t.Fatalf("params variant lost payload or existing query: %s", variants[0])
	}
	if !strings.Contains(variants[1], "#") || !strings.Contains(variants[1], "__SF__1") {
		t.Fatalf("hash variant malformed: %s", variants[1])
	}
}

// TestRunWithoutBrowser exercises the whole module plumbing: dry run, and
// non-dry run with an unresolvable browser binary.
func TestRunWithoutBrowser(t *testing.T) {
	run := testRun(t)
	runCtx := modules.NewRunContext("a.example", "web", false, run)
	secrets := filepath.Join(run.Path("06_vulns"), "js-secrets.jsonl")
	if err := os.MkdirAll(filepath.Dir(secrets), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeJSONL(t, secrets, []interface{}{
		findingLine("https://a.example/app.js", "dom-sink", "eval-call", "high", []string{`alert(1)`}),
	})
	if err := runCtx.AddArtifact("js_secrets", modules.Artifact{Name: "js_secrets", Type: "jsonl", Path: "06_vulns/js-secrets.jsonl"}); err != nil {
		t.Fatalf("add artifact: %v", err)
	}

	crawled := filepath.Join(run.Path("05_content"), "crawled.txt")
	if err := os.MkdirAll(filepath.Dir(crawled), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(crawled, []byte("https://a.example/\n"), 0644); err != nil {
		t.Fatalf("write crawl fixture: %v", err)
	}
	if err := runCtx.AddArtifact("crawled_urls", modules.Artifact{Name: "crawled_urls", Type: "text", Path: "05_content/crawled.txt"}); err != nil {
		t.Fatalf("add artifact: %v", err)
	}

	mod := New("/nonexistent/chromium")
	result, err := mod.Run(context.Background(), runCtx, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("status = %q, want completed", result.Status)
	}

	lines, err := readVerdictLines(run.Path("06_vulns", "js-verified.jsonl"))
	if err != nil {
		t.Fatalf("read verdicts: %v", err)
	}
	if len(lines) != 1 {
		t.Fatalf("verdicts = %d, want 1 (browser-unavailable notice)", len(lines))
	}
	if lines[0].Pattern != "skipped" || lines[0].Verdict != "not-observed" {
		t.Fatalf("unexpected notice verdict: %+v", lines[0])
	}

	// The artifact must be published so downstream consumers can read it.
	if art, ok := runCtx.GetArtifact("js_verified"); !ok || art.Path != "06_vulns/js-verified.jsonl" {
		t.Fatalf("js_verified artifact missing: %+v", art)
	}

	// With no browser the audit trail records why nothing was launched.
	log, err := os.ReadFile(run.CommandsLog)
	if err != nil {
		t.Fatalf("read commands log: %v", err)
	}
	if !strings.Contains(string(log), "-browser unavailable") {
		t.Fatalf("commands log does not explain the missing browser:\n%s", log)
	}
}

func TestRunDryRunWritesEmptyVerdicts(t *testing.T) {
	run := testRun(t)
	runCtx := modules.NewRunContext("a.example", "web", true, run)

	secrets := filepath.Join(run.Path("06_vulns"), "js-secrets.jsonl")
	if err := os.MkdirAll(filepath.Dir(secrets), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeJSONL(t, secrets, []interface{}{
		findingLine("https://a.example/app.js", "dom-sink", "eval-call", "high", []string{`alert(1)`}),
	})
	if err := runCtx.AddArtifact("js_secrets", modules.Artifact{Name: "js_secrets", Type: "jsonl", Path: "06_vulns/js-secrets.jsonl"}); err != nil {
		t.Fatalf("add artifact: %v", err)
	}
	crawled := filepath.Join(run.Path("05_content"), "crawled.txt")
	if err := os.MkdirAll(filepath.Dir(crawled), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(crawled, []byte("https://a.example/\n"), 0644); err != nil {
		t.Fatalf("write crawl fixture: %v", err)
	}
	if err := runCtx.AddArtifact("crawled_urls", modules.Artifact{Name: "crawled_urls", Type: "text", Path: "05_content/crawled.txt"}); err != nil {
		t.Fatalf("add artifact: %v", err)
	}

	mod := New("")
	if _, err := mod.Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
	lines, err := readVerdictLines(run.Path("06_vulns", "js-verified.jsonl"))
	if err != nil {
		t.Fatalf("read verdicts: %v", err)
	}
	if len(lines) != 0 {
		t.Fatalf("dry-run verdicts = %d, want 0", len(lines))
	}
}

// TestReplayLocalVulnerablePage is the end-to-end check of the verification
// engine: a page that copies the fragment into innerHTML, reads the q query
// parameter into innerHTML, and relays postMessage data into innerHTML. The
// replay must classify the payload as executed (the img onerror handler runs
// after the sink assigns it) instead of not-observed. It needs a real chrome
// binary, so it self-skips when none is available, and it is skipped on CI:
// some runners expose a chrome binary that never answers the CDP websocket,
// which only proves the test environment is broken, not the replay engine.
func TestReplayLocalVulnerablePage(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("browser launch is not reliable on CI runners")
	}
	chrome := detectBrowser()
	if chrome == "" {
		t.Skip("no chrome/chromium binary available")
	}

	page := `<html><body>
<div id="a"></div><div id="b"></div>
<script>
document.getElementById("a").innerHTML = location.hash.slice(1);
document.getElementById("b").innerHTML = new URLSearchParams(location.search).get("q");
window.addEventListener("message", function (e) { document.getElementById("b").innerHTML = e.data; });
</script>
</body></html>`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(page))
	}))
	defer server.Close()

	item := finding{
		URL:      server.URL + "/app.js",
		Kind:     "dom-sink",
		Pattern:  "html-assignment",
		Severity: "high",
		Payloads: []string{`<img src=x onerror=alert(1)>`},
	}
	payload := markPayload(item.Payloads[0], 0)

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), chromedp.ExecPath(chrome), chromedp.Headless, chromedp.NoSandbox)
	defer allocCancel()
	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	defer browserCancel()

	out := replayOne(browserCtx, item, server.URL+"/", payload)
	if out.Verdict != "executed" {
		t.Fatalf("verdict = %q (evidence %q), want executed on the vulnerable page", out.Verdict, out.Evidence)
	}
}

// TestReplaySafePageNotObserved guards the URL-check regression: a page that
// ignores fragment, params and postMessage must yield not-observed, never a
// sink-reached verdict derived from our own injected hash/params. It needs a
// real chrome binary and is skipped on CI like TestReplayLocalVulnerablePage.
func TestReplaySafePageNotObserved(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("browser launch is not reliable on CI runners")
	}
	chrome := detectBrowser()
	if chrome == "" {
		t.Skip("no chrome/chromium binary available")
	}

	page := `<html><body><script>document.title = "safe";</script></body></html>`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(page))
	}))
	defer server.Close()

	item := finding{
		URL:      server.URL + "/app.js",
		Kind:     "dom-sink",
		Pattern:  "html-assignment",
		Severity: "high",
		Payloads: []string{`<img src=x onerror=alert(1)>`},
	}
	payload := markPayload(item.Payloads[0], 0)

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), chromedp.ExecPath(chrome), chromedp.Headless, chromedp.NoSandbox)
	defer allocCancel()
	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	defer browserCancel()

	out := replayOne(browserCtx, item, server.URL+"/", payload)
	if out.Verdict != "not-observed" {
		t.Fatalf("verdict = %q (evidence %q), want not-observed on the safe page", out.Verdict, out.Evidence)
	}
}

func readVerdictLines(path string) ([]verdict, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []verdict
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var v verdict
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func TestVerdictJSONShape(t *testing.T) {
	v := verdict{URL: "u", Page: "p", Kind: "dom-sink", Pattern: "eval-call", Severity: "high", Payload: "alert(1)", Verdict: "executed", Evidence: "e"}
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back map[string]interface{}
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"url", "page", "kind", "pattern", "severity", "payload", "verdict", "evidence"} {
		if _, ok := back[key]; !ok {
			t.Errorf("verdict JSON missing %q: %s", key, data)
		}
	}
}

func TestDetectBrowserNone(t *testing.T) {
	// The PATH lookup is the only variable part; on CI there is no chrome.
	// We only assert the function shape: it returns a path or empty string.
	got := detectBrowser()
	if got != "" && !strings.Contains(got, string(os.PathSeparator)) {
		t.Fatalf("detectBrowser = %q, expected path or empty", got)
	}
}

func TestChromiumLaunchCommandFlags(t *testing.T) {
	cmd := chromiumLaunchCommand("/opt/chrome/chrome", "")
	if cmd.Name != "/opt/chrome/chrome" {
		t.Fatalf("Name = %q, want browser path", cmd.Name)
	}
	for _, want := range []string{"--headless", "--no-sandbox", "--disable-gpu"} {
		found := false
		for _, arg := range cmd.Args {
			if arg == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("args %v missing %q", cmd.Args, want)
		}
	}
	for _, arg := range cmd.Args {
		if strings.HasPrefix(arg, "--proxy-server=") {
			t.Fatalf("args %v unexpectedly carry a proxy flag", cmd.Args)
		}
	}

	proxied := chromiumLaunchCommand("/opt/chrome/chrome", "127.0.0.1:8080")
	found := false
	for _, arg := range proxied.Args {
		if arg == "--proxy-server=127.0.0.1:8080" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("proxy flag missing from %v", proxied.Args)
	}
}

func TestRunDryRunAuditsRealLaunchCommand(t *testing.T) {
	run := testRun(t)
	runCtx := modules.NewRunContext("a.example", "web", true, run)

	secrets := filepath.Join(run.Path("06_vulns"), "js-secrets.jsonl")
	if err := os.MkdirAll(filepath.Dir(secrets), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeJSONL(t, secrets, []interface{}{
		findingLine("https://a.example/app.js", "dom-sink", "eval-call", "high", []string{`alert(1)`}),
	})
	if err := runCtx.AddArtifact("js_secrets", modules.Artifact{Name: "js_secrets", Type: "jsonl", Path: "06_vulns/js-secrets.jsonl"}); err != nil {
		t.Fatalf("add artifact: %v", err)
	}
	crawled := filepath.Join(run.Path("05_content"), "crawled.txt")
	if err := os.MkdirAll(filepath.Dir(crawled), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(crawled, []byte("https://a.example/\n"), 0644); err != nil {
		t.Fatalf("write crawl fixture: %v", err)
	}
	if err := runCtx.AddArtifact("crawled_urls", modules.Artifact{Name: "crawled_urls", Type: "text", Path: "05_content/crawled.txt"}); err != nil {
		t.Fatalf("add artifact: %v", err)
	}

	browser := filepath.Join(run.RootDir, "fake-chrome")
	if err := os.WriteFile(browser, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write fake browser: %v", err)
	}

	if _, err := New(browser).Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Even without launching anything, dry-run must audit the exact binary
	// and flags chromedp would start — not a synthetic placeholder.
	log, err := os.ReadFile(run.CommandsLog)
	if err != nil {
		t.Fatalf("read commands log: %v", err)
	}
	line := "$ " + browser + " --headless --no-sandbox --disable-gpu\n"
	if !strings.Contains(string(log), line) {
		t.Fatalf("commands log misses the real launch command:\n%s", log)
	}
}

// testRun builds a minimal run directory like the sibling module tests.
func testRun(t *testing.T) *storage.Run {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"00_meta", "05_content", "06_vulns"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	return &storage.Run{
		RootDir:     root,
		MetaDir:     filepath.Join(root, "00_meta"),
		CommandsLog: filepath.Join(root, "00_meta", "commands.log"),
	}
}
