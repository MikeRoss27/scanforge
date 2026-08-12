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
	"sync"
	"sync/atomic"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

func TestRequiresAndProduces(t *testing.T) {
	if got, want := New().Requires(), []string{"crawled_urls"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Requires() = %v, want %v", got, want)
	}
	if got, want := New().Produces(), []string{"js_secrets", "js_payloads"}; !reflect.DeepEqual(got, want) {
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

	var mu sync.Mutex
	var live []modules.Finding
	runCtx.SetFindingSink(func(f modules.Finding) {
		mu.Lock()
		live = append(live, f)
		mu.Unlock()
	})

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

	mu.Lock()
	defer mu.Unlock()
	if len(live) != 1 {
		t.Fatalf("live findings = %+v, want exactly 1", live)
	}
	if live[0].Module != "jssecrets" || live[0].Severity != "critical" || live[0].Target != server.URL+"/app.js" {
		t.Fatalf("unexpected live finding: %+v", live[0])
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

func TestScanBodyInternalHostnameSkipsPropertyAccess(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantFlag bool
	}{
		{"minified identifier property access", `const e = {internal: 1}; if (e.internal) report(e);`, false},
		{"this property access", `const x = this.internal || {};`, false},
		{"chained property access", `config.env.internal.value;`, false},
		{"quoted internal hostname", `const api = "payments.internal";`, true},
		{"url internal hostname", `fetch("https://payments.internal/charge");`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scanBody("https://target.example/app.js", tc.body)
			flagged := false
			for _, f := range findings {
				if f.Pattern == "internal-hostname" {
					flagged = true
				}
			}
			if flagged != tc.wantFlag {
				t.Fatalf("internal-hostname flagged = %v, want %v (findings: %+v)", flagged, tc.wantFlag, findings)
			}
		})
	}
}

const (
	// tmdbPublicJWT is TMDB's well-known public API key JWT, shipped in every
	// TMDB client integration; its aud claim is the public key itself.
	tmdbPublicJWT = "eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiI1ODRlMGVhYWRlMDUwODA0Mzg2OTIyNDNiNGFlMDY5ZCIsIm5iZiI6MTc1MzczMDk3MS41MzYsInN1YiI6IjY4ODdjZjliNzMwYWI1NzJiNjhhNzQyOCIsInNjb3BlcyI6WyJhcGlfcmVhZCJdLCJ2ZXJzaW9uIjoxfQ.Uq9psYif6KREYJCByaABi3Yq4WYEzeF8e-zTobEPucw"
	// randomJWT is a syntactically valid JWT with an audience that is not
	// whitelisted and must therefore still be reported.
	randomJWT = "eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJzb21lLWNsaWVudCIsImV4cCI6MTk5OTk5OTk5OX0.RZrVbQwErTyUiOpAsDfGhJkLzXcVbNmQ1"
)

func TestScanBodyJWTWhitelistsPublicAudience(t *testing.T) {
	body := `const tmdb = "` + tmdbPublicJWT + `";`
	findings := scanBody("https://target.example/app.js", body)
	for _, f := range findings {
		if f.Pattern == "jwt" {
			t.Fatalf("public TMDB JWT was flagged: %+v", f)
		}
	}

	body = `const jwt = "` + randomJWT + `";`
	findings = scanBody("https://target.example/app.js", body)
	var flagged bool
	for _, f := range findings {
		if f.Pattern == "jwt" {
			flagged = true
			if f.Match != randomJWT {
				t.Fatalf("jwt match = %q, want the full token", f.Match)
			}
		}
	}
	if !flagged {
		t.Fatalf("random JWT was not flagged, findings: %+v", findings)
	}
}

func TestScanSourceMapsOnlyWhenReachable(t *testing.T) {
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
	runCtx := modules.NewRunContext("example.com", "web", false, nil)
	found := scanSourceMaps(context.Background(), runCtx, client, server.URL+"/app.js", appBody, nil)
	if len(found) == 0 {
		t.Fatal("expected a reachable source map to be reported")
	}
	mapFinding := found[0]
	if mapFinding.Kind != "source-map" || mapFinding.Match != server.URL+"/app.js.map" {
		t.Fatalf("finding = %+v, want source-map at %s/app.js.map", mapFinding, server.URL)
	}

	goneBody := "console.log(1);\n//# sourceMappingURL=gone.js.map\n"
	if got := scanSourceMaps(context.Background(), runCtx, client, server.URL+"/gone.js", goneBody, nil); len(got) != 0 {
		t.Fatalf("expected a 404 source map to be skipped, got %+v", got)
	}
}

func TestScanSourceMapsScansOriginalSources(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("console.log(1);\n//# sourceMappingURL=app.js.map\n"))
	})
	mux.HandleFunc("/app.js.map", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"version":3,"sources":["app.ts"],"sourcesContent":["const dbPassword = 'Kx9mQ2vR7tY4wN8pL1zX5cV3bG6hJ0fD8sA2';"]}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := server.Client()

	found := scanSourceMaps(context.Background(), modules.NewRunContext("example.com", "web", false, nil), client, server.URL+"/app.js",
		"console.log(1);\n//# sourceMappingURL=app.js.map\n", nil)
	if len(found) < 2 {
		t.Fatalf("expected source-map finding + secret from original source, got %+v", found)
	}
	if found[0].Pattern != "exposed-source-map" {
		t.Fatalf("first finding = %+v, want the map exposure", found[0])
	}
}

func TestChaseImportsFindsLazyChunks(t *testing.T) {
	body := strings.Join([]string{
		`import("./chunk.abc123.js");`,
		`const url = new URL("vendor.js?v=2", import.meta.url);`,
		`import("./data.json");`,
		`const other = import("/abs/path/admin.mjs");`,
	}, "\n")

	got := chaseImports("https://example.com/assets/app.js", body)
	want := []string{
		"https://example.com/assets/chunk.abc123.js",
		"https://example.com/abs/path/admin.mjs",
		"https://example.com/assets/vendor.js?v=2",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("chaseImports = %v, want %v", got, want)
	}
}

func TestChaseImportsIgnoresNonJS(t *testing.T) {
	body := `import("./style.css"); import("https://cdn.other.test/lib.js");`
	got := chaseImports("https://example.com/assets/app.js", body)
	want := []string{"https://cdn.other.test/lib.js"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("chaseImports = %v, want %v (css skipped, absolute JS kept)", got, want)
	}
}

func TestScanBodyFlagsHighEntropySecret(t *testing.T) {
	body := `var config = {"apiKey": "qW7zR4tY8uI2pL5sX9vB3nM6jH1kF8dA2cG5zE7wQ9rT1yU4iO6pA3sD9fG2hJ5kL8mN1vB4xZ7cV2"};`
	findings := scanBody("https://target.example/app.js", body)
	var found bool
	for _, f := range findings {
		if f.Pattern == "high-entropy-secret" {
			found = true
			if f.Severity != "medium" || f.Match == "" {
				t.Fatalf("bad entropy finding: %+v", f)
			}
		}
	}
	if !found {
		t.Fatalf("expected a high-entropy finding, got %+v", findings)
	}
}

func TestScanBodySkipsLowEntropyValues(t *testing.T) {
	body := `var config = {"apiKey": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};`
	findings := scanBody("https://target.example/app.js", body)
	for _, f := range findings {
		if f.Pattern == "high-entropy-secret" {
			t.Fatalf("low-entropy value flagged: %+v", f)
		}
	}
}

func TestRunChasesDynamicImports(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`import("./chunk.js"); console.log("boot");` + "\n"))
	})
	mux.HandleFunc("/chunk.js", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("var token = 'SG.aaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';\n"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	run := testRun(t)
	writeCrawledURLs(t, run, server.URL+"/app.js\n")
	runCtx := newRunContext(t, run, false)

	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	findings := readFindings(t, run.Path("06_vulns", "js-secrets.jsonl"))
	var found bool
	for _, f := range findings {
		if f.Pattern == "sendgrid-api-key" && f.URL == server.URL+"/chunk.js" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a sendgrid key found in the chased chunk, got %+v", findings)
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

func TestRunReportsDangerousPatternsAndPayloads(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(strings.Join([]string{
			`var view = document.getElementById("preview");`,
			`view.innerHTML = location.hash;`,
			`eval(params.code);`,
		}, "\n")))
	}))
	defer server.Close()

	run := testRun(t)
	writeCrawledURLs(t, run, server.URL+"/app.js\n")
	runCtx := newRunContext(t, run, false)

	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if _, ok := runCtx.GetArtifact("js_payloads"); !ok {
		t.Fatal("js_payloads artifact was not published")
	}

	findings := readFindings(t, run.Path("06_vulns", "js-secrets.jsonl"))
	var html, evalFinding *finding
	for _, f := range findings {
		switch f.Pattern {
		case "html-assignment":
			html = &f
		case "eval-call":
			evalFinding = &f
		}
	}
	if html == nil || evalFinding == nil {
		t.Fatalf("expected html-assignment and eval-call findings, got %+v", findings)
	}
	if html.URL != server.URL+"/app.js" || html.Line != 2 || html.Snippet == "" {
		t.Fatalf("bad html finding: %+v", html)
	}
	if len(evalFinding.Payloads) == 0 {
		t.Fatalf("eval finding should carry payloads: %+v", evalFinding)
	}

	payloadFile := run.Path("06_vulns", "js-payloads.txt")
	data, err := os.ReadFile(payloadFile)
	if err != nil {
		t.Fatalf("payloads file missing: %v", err)
	}
	flat := string(data)
	for _, p := range evalFinding.Payloads {
		if !strings.Contains(flat, p) {
			t.Errorf("payload %q missing from %s", p, payloadFile)
		}
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
