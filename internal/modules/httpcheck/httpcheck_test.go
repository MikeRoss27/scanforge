package httpcheck

import (
	"context"
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
	if got, want := New().Requires(), []string{"attack_surface_urls"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Requires() = %v, want %v", got, want)
	}
	if got, want := New().Produces(), []string{"http_checks"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Produces() = %v, want %v", got, want)
	}
}

func TestEvaluateHeadersFlagsGaps(t *testing.T) {
	header := http.Header{}
	header.Set("Set-Cookie", "session=abc; Path=/")
	found := evaluateHeaders("https://example.com/", header)
	byCheck := make(map[string]check)
	for _, c := range found {
		byCheck[c.Check] = c
	}

	for _, want := range []string{"missing-csp", "missing-hsts", "missing-x-frame-options", "missing-nosniff", "missing-referrer-policy", "missing-permissions-policy", "cookie-without-secure", "cookie-without-httponly"} {
		if _, ok := byCheck[want]; !ok {
			t.Errorf("missing check %q in %+v", want, found)
		}
	}
	if got := byCheck["cookie-without-secure"].Detail; !strings.Contains(got, "session") {
		t.Errorf("cookie check detail = %q, want cookie name", got)
	}
}

func TestEvaluateHeadersAcceptsGoodConfig(t *testing.T) {
	header := http.Header{}
	header.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	header.Set("Strict-Transport-Security", "max-age=31536000")
	header.Set("X-Frame-Options", "DENY")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Permissions-Policy", "geolocation=()")
	header.Set("Set-Cookie", "session=abc; Secure; HttpOnly; Path=/")

	found := evaluateHeaders("https://example.com/", header)
	if len(found) != 0 {
		t.Fatalf("expected no checks for a hardened response, got %+v", found)
	}
}

func TestEvaluateHeadersHSTSOnlyOverHTTPS(t *testing.T) {
	header := http.Header{}

	if found := evaluateHeaders("http://example.com/", header); containsCheck(found, "missing-hsts") {
		t.Fatalf("plain HTTP target must not be flagged for HSTS, got %+v", found)
	}
	if found := evaluateHeaders("https://example.com/", header); !containsCheck(found, "missing-hsts") {
		t.Fatalf("HTTPS target missing HSTS must be flagged, got %+v", found)
	}
}

func TestCookieFlagsParsesAttributes(t *testing.T) {
	tests := []struct {
		name     string
		cookie   string
		wantName string
		wantSec  bool
		wantHTTP bool
	}{
		{"plain", "session=abc; Path=/", "session", false, false},
		{"both flags", "session=abc; Secure; HttpOnly; Path=/", "session", true, true},
		{"case-insensitive", "token=xyz; secure; httponly", "token", true, true},
		{"value looks secure", "state=insecure; Path=/", "state", false, false},
		{"boolean false value still sets flag", "sid=1; HttpOnly=false; Secure=false", "sid", true, true},
		{"no equals", "customcookie; Secure", "customcookie", true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name, secure, httpOnly := cookieFlags(tc.cookie)
			if name != tc.wantName || secure != tc.wantSec || httpOnly != tc.wantHTTP {
				t.Fatalf("cookieFlags(%q) = (%q, %v, %v), want (%q, %v, %v)",
					tc.cookie, name, secure, httpOnly, tc.wantName, tc.wantSec, tc.wantHTTP)
			}
		})
	}
}

func TestInspectURLCrossHostRedirectNotAttributed(t *testing.T) {
	var external atomic.Int64
	externalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		external.Add(1)
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
	}))
	defer externalServer.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, externalServer.URL, http.StatusFound)
	}))
	defer redirector.Close()

	found := inspectURL(context.Background(), &http.Client{Timeout: requestTimeout}, redirector.URL, nil)
	if len(found) != 0 {
		t.Fatalf("cross-host redirect must not produce findings, got %+v", found)
	}
	if external.Load() == 0 {
		t.Fatal("redirect was not followed; test is inconclusive")
	}
}

func TestReadURLsDeduplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "surface.txt")
	if err := os.WriteFile(path, []byte("https://a.example/\nhttps://a.example/\n\nhttps://b.example/\n"), 0644); err != nil {
		t.Fatal(err)
	}
	urls, err := readURLs(path)
	if err != nil {
		t.Fatalf("readURLs() error = %v", err)
	}
	if len(urls) != 2 || urls[0] != "https://a.example/" || urls[1] != "https://b.example/" {
		t.Fatalf("readURLs() = %v, want deduplicated [https://a.example/ https://b.example/]", urls)
	}
}

func TestReadURLsSkipsStaticAssets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "surface.txt")
	content := "https://x.com/app.js\nhttps://x.com/assets/main.css\nhttps://x.com/logo.png?size=2\nhttps://x.com/\nhttps://x.com/api/v1\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	urls, err := readURLs(path)
	if err != nil {
		t.Fatalf("readURLs() error = %v", err)
	}
	if len(urls) != 2 || urls[0] != "https://x.com/" || urls[1] != "https://x.com/api/v1" {
		t.Fatalf("readURLs() = %v, want static assets filtered out, keeping [https://x.com/ https://x.com/api/v1]", urls)
	}
}

func TestIsStaticAsset(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{"js asset", "https://x.com/app.js", true},
		{"css asset", "https://x.com/assets/main.css", true},
		{"png asset with query", "https://x.com/logo.png?size=2", true},
		{"robots.txt is not an asset", "https://x.com/robots.txt", false},
		{"root path", "https://x.com/", false},
		{"service worker is not an asset", "https://x.com/sw.js", false},
		{"html page", "https://x.com/index.html", false},
		{"api path", "https://x.com/api/v1", false},
		{"json data", "https://x.com/data.json", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isStaticAsset(tc.raw); got != tc.want {
				t.Fatalf("isStaticAsset(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestRunDeduplicatesFindingsPerHost(t *testing.T) {
	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "sid=xyz; Path=/")
		_, _ = w.Write([]byte("ok"))
	}
	hostA := httptest.NewServer(http.HandlerFunc(handler))
	defer hostA.Close()
	hostB := httptest.NewServer(http.HandlerFunc(handler))
	defer hostB.Close()

	run := testRun(t)
	writeURLs(t, run, hostA.URL+"/\n"+hostA.URL+"/admin\n"+hostB.URL+"/\n")
	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if err := runCtx.AddArtifact("attack_surface_urls", modules.Artifact{Name: "attack_surface_urls", Type: "text", Path: "04_surface/attack-surface.txt"}); err != nil {
		t.Fatal(err)
	}

	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	data, err := os.ReadFile(run.Path(outputRel))
	if err != nil {
		t.Fatal(err)
	}
	count := func(name string) int {
		return strings.Count(string(data), `"check":"`+name+`"`)
	}
	// missing-hsts is excluded: httptest servers speak plain HTTP and HSTS is
	// only flagged over HTTPS, but it goes through the same dedup path.
	for _, name := range []string{"missing-csp", "missing-x-frame-options", "missing-nosniff", "missing-referrer-policy", "missing-permissions-policy", "cookie-without-secure", "cookie-without-httponly"} {
		if got := count(name); got != 2 {
			t.Fatalf("%s findings = %d, want 2 (one per host), data:\n%s", name, got, data)
		}
	}
}

func containsCheck(checks []check, name string) bool {
	for _, c := range checks {
		if c.Check == name {
			return true
		}
	}
	return false
}

func TestRunChecksLiveServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "sid=xyz; Path=/")
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	run := testRun(t)
	writeURLs(t, run, server.URL+"/\n")
	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if err := runCtx.AddArtifact("attack_surface_urls", modules.Artifact{Name: "attack_surface_urls", Type: "text", Path: "04_surface/attack-surface.txt"}); err != nil {
		t.Fatal(err)
	}

	result, err := New().Run(context.Background(), runCtx, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("Run() status = %q, want completed", result.Status)
	}
	if _, ok := runCtx.GetArtifact("http_checks"); !ok {
		t.Fatal("http_checks artifact was not published")
	}

	data, err := os.ReadFile(run.Path(outputRel))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "cookie-without-secure") {
		t.Fatalf("expected cookie finding, got %q", data)
	}
	if strings.Contains(string(data), "missing-hsts") {
		t.Fatalf("plain HTTP target must not be flagged for HSTS, got %q", data)
	}
}

func TestRunDryRunMakesNoRequests(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()

	run := testRun(t)
	writeURLs(t, run, server.URL+"/\n")
	runCtx := modules.NewRunContext("example.com", "web", true, run)
	if err := runCtx.AddArtifact("attack_surface_urls", modules.Artifact{Name: "attack_surface_urls", Type: "text", Path: "04_surface/attack-surface.txt"}); err != nil {
		t.Fatal(err)
	}

	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("dry run issued %d requests, want 0", got)
	}
	info, err := os.Stat(run.Path(outputRel))
	if err != nil {
		t.Fatalf("output missing: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("output size = %d, want empty", info.Size())
	}
}

func testRun(t *testing.T) *storage.Run {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"00_meta", "04_surface", "06_vulns"} {
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

func writeURLs(t *testing.T, run *storage.Run, content string) {
	t.Helper()
	if err := os.WriteFile(run.Path("04_surface", "attack-surface.txt"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
