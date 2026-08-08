package jssecrets

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

func TestRequiresAndProduces(t *testing.T) {
	if got, want := New().Requires(), []string{"crawled_urls"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Requires() = %v, want %v", got, want)
	}
	if got, want := New().Produces(), []string{"js_secrets"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Produces() = %v, want %v", got, want)
	}
}

func TestIsJavaScriptURL(t *testing.T) {
	cases := map[string]bool{
		"https://example.com/app.js":              true,
		"https://example.com/app.js?v=2":          true,
		"https://example.com/static/main.mjs":     true,
		"https://example.com/static/MAIN.MJS":     true,
		"https://example.com/bundle.JS#frag":      true,
		"https://example.com/data.json":           false,
		"https://example.com/data.json?x=app.js":  false,
		"https://example.com/component.jsx":       false,
		"https://example.com/":                    false,
		"https://example.com/jsonp?callback=a.js": false,
	}
	for raw, want := range cases {
		if got := isJavaScriptURL(raw); got != want {
			t.Errorf("isJavaScriptURL(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestRunFlagsSecretInFetchedJS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte("var conf = {region: 'us-east-1', id: 'AKIAIOSFODNN7EXAMPLE'};\n"))
	}))
	defer server.Close()

	run := testRun(t)
	writeCrawledURLs(t, run, server.URL+"/app.js\n"+server.URL+"/index.html\n")
	runCtx := newRunContext(t, run, false)

	result, err := New().Run(context.Background(), runCtx, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("Run() status = %q, want completed", result.Status)
	}
	if _, ok := runCtx.GetArtifact("js_secrets"); !ok {
		t.Fatal("js_secrets artifact was not published")
	}

	findings := readFindings(t, run.Path("06_vulns", "js-secrets.jsonl"))
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly 1", findings)
	}
	if findings[0].Kind != "secret" || findings[0].Pattern != "aws-access-key-id" || findings[0].Severity != "critical" {
		t.Fatalf("finding = %+v, want secret/aws-access-key-id/critical", findings[0])
	}
	if findings[0].Match != "AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("finding match = %q, want the full unredacted key", findings[0].Match)
	}
	if findings[0].URL != server.URL+"/app.js" {
		t.Fatalf("finding url = %q, want %q", findings[0].URL, server.URL+"/app.js")
	}
}

func TestRunWritesEmptyFileWithoutFindings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("console.log('nothing to see here');\n"))
	}))
	defer server.Close()

	run := testRun(t)
	writeCrawledURLs(t, run, server.URL+"/app.js\n")
	runCtx := newRunContext(t, run, false)

	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	info, err := os.Stat(run.Path("06_vulns", "js-secrets.jsonl"))
	if err != nil {
		t.Fatalf("output file missing: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("output size = %d, want an empty file", info.Size())
	}
}

func TestRunDryRunMakesNoRequests(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("var key = 'AKIAIOSFODNN7EXAMPLE';\n"))
	}))
	defer server.Close()

	run := testRun(t)
	writeCrawledURLs(t, run, server.URL+"/app.js\n")
	runCtx := newRunContext(t, run, true)

	result, err := New().Run(context.Background(), runCtx, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("Run() status = %q, want completed", result.Status)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("dry run issued %d HTTP requests, want 0", got)
	}
	if _, ok := runCtx.GetArtifact("js_secrets"); !ok {
		t.Fatal("js_secrets artifact was not published")
	}
	if _, err := os.Stat(run.Path("06_vulns", "js-secrets.jsonl")); err != nil {
		t.Fatalf("output file missing: %v", err)
	}
}

func TestScanBodyDetectsEveryCategory(t *testing.T) {
	body := strings.Join([]string{
		`const bucket = "https://my-app-uploads.s3.amazonaws.com/file.pdf";`,
		`const internalHost = "http://payments.internal/charge";`,
		`const internalIP = "10.0.4.12";`,
		`const contact = "security-team@acmecorp.io";`,
		`const placeholder = "you@example.com";`,
		`fetch("/api/v2/users/{id}/export");`,
		`fetch("/assets/logo.png");`,
	}, "\n")

	findings := scanBody("https://target.example/app.js", body)

	byKindPattern := map[string]finding{}
	for _, f := range findings {
		byKindPattern[f.Kind+":"+f.Pattern] = f
	}

	cases := []struct {
		key   string
		match string
	}{
		{"cloud-storage:aws-s3-bucket", "my-app-uploads.s3.amazonaws.com"},
		{"internal-host:internal-hostname", "payments.internal"},
		{"internal-host:internal-ipv4-address", "10.0.4.12"},
		{"email:email-address", "security-team@acmecorp.io"},
		{"endpoint:sensitive-api-endpoint", "/api/v2/users/{id}/export"},
	}
	for _, tc := range cases {
		got, ok := byKindPattern[tc.key]
		if !ok {
			t.Errorf("missing finding for %s (got: %+v)", tc.key, findings)
			continue
		}
		if got.Match != tc.match {
			t.Errorf("%s match = %q, want %q", tc.key, got.Match, tc.match)
		}
	}

	for key := range byKindPattern {
		if strings.Contains(key, "example.com") {
			t.Errorf("placeholder email should have been filtered, got %s", key)
		}
	}
	if _, ok := byKindPattern["email:email-address"]; ok {
		for _, f := range findings {
			if f.Kind == "email" && strings.Contains(f.Match, "example.com") {
				t.Errorf("placeholder email leaked into findings: %+v", f)
			}
		}
	}
	for _, f := range findings {
		if strings.Contains(f.Match, "logo.png") {
			t.Errorf("static asset path should not be treated as a sensitive endpoint: %+v", f)
		}
	}
}

func TestDetectSourceMapOnlyWhenReachable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("console.log(1);\n//# sourceMappingURL=app.js.map\n"))
	})
	mux.HandleFunc("/app.js.map", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"version":3,"sources":["app.ts"]}`))
	})
	mux.HandleFunc("/gone.js", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("console.log(1);\n//# sourceMappingURL=gone.js.map\n"))
	})
	mux.HandleFunc("/gone.js.map", func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := server.Client()

	appBody := "console.log(1);\n//# sourceMappingURL=app.js.map\n"
	found := detectSourceMap(context.Background(), client, server.URL+"/app.js", appBody, nil)
	if found == nil {
		t.Fatal("expected a reachable source map to be reported")
	}
	if found.Kind != "source-map" || found.Match != server.URL+"/app.js.map" {
		t.Fatalf("finding = %+v, want source-map at %s/app.js.map", found, server.URL)
	}

	goneBody := "console.log(1);\n//# sourceMappingURL=gone.js.map\n"
	if got := detectSourceMap(context.Background(), client, server.URL+"/gone.js", goneBody, nil); got != nil {
		t.Fatalf("expected a 404 source map to be skipped, got %+v", got)
	}
}

func TestRunToleratesMissingInputFile(t *testing.T) {
	run := testRun(t)
	runCtx := newRunContext(t, run, true)

	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if _, err := os.Stat(run.Path("06_vulns", "js-secrets.jsonl")); err != nil {
		t.Fatalf("output file missing: %v", err)
	}
}

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

func newRunContext(t *testing.T, run *storage.Run, dryRun bool) *modules.RunContext {
	t.Helper()
	runCtx := modules.NewRunContext("example.com", "web", dryRun, run)
	if err := runCtx.AddArtifact("crawled_urls", modules.Artifact{
		Name: "crawled_urls", Type: "text", Path: "05_content/katana.txt",
	}); err != nil {
		t.Fatal(err)
	}
	return runCtx
}

func writeCrawledURLs(t *testing.T, run *storage.Run, content string) {
	t.Helper()
	if err := os.WriteFile(run.Path("05_content", "katana.txt"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func readFindings(t *testing.T, path string) []finding {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()

	var findings []finding
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var item finding
		if err := json.Unmarshal(scanner.Bytes(), &item); err != nil {
			t.Fatalf("invalid JSONL line %q: %v", scanner.Text(), err)
		}
		findings = append(findings, item)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return findings
}
