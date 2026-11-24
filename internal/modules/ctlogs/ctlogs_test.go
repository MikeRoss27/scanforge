package ctlogs

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
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	scanScope "github.com/MikeRoss27/scanforge/internal/scope"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

var fastRetry = modules.RetryPolicy{Attempts: 3, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond}

// rewriteFetcher sends every request to the httptest server instead of the
// real crt.sh while recording the URL the module asked for.
type rewriteFetcher struct {
	inner modules.Fetcher
	base  string
	asked []string
}

func (f *rewriteFetcher) Get(ctx context.Context, raw string) (*modules.FetchResult, error) {
	f.asked = append(f.asked, raw)
	return f.inner.Get(ctx, f.base+strings.TrimPrefix(raw, baseURL))
}

func newRun(t *testing.T) *storage.Run {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"00_meta", "01_subdomains"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0755); err != nil {
			t.Fatal(err)
		}
	}
	return &storage.Run{RootDir: root, MetaDir: filepath.Join(root, "00_meta"), CommandsLog: filepath.Join(root, "00_meta", "commands.log")}
}

func fixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "crtsh_sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseNamesNormalizesDedupesAndDropsJunk(t *testing.T) {
	got, err := ParseNames(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"api.example.com", "cdn.example.com", "dev.example.com", "example.com",
		"other-tenant.net", "staging.example.com", "www.example.com",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseNames = %v, want %v", got, want)
	}
}

func TestParseNamesEmptyAndInvalid(t *testing.T) {
	if names, err := ParseNames([]byte("  \n")); err != nil || len(names) != 0 {
		t.Fatalf("empty body: %v %v", names, err)
	}
	if _, err := ParseNames([]byte("<html>502</html>")); err == nil {
		t.Fatal("expected error on non-JSON body")
	}
}

func TestQueryURL(t *testing.T) {
	if got, want := QueryURL("example.com"), "https://crt.sh/?q=%25.example.com&output=json"; got != want {
		t.Fatalf("QueryURL = %q, want %q", got, want)
	}
}

func TestRunRetriesFiltersScopeAndLogsRejections(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			http.Error(w, "busy", http.StatusBadGateway) // crt.sh flakiness
			return
		}
		if r.URL.Query().Get("output") != "json" || r.URL.Query().Get("q") != "%.example.com" {
			t.Errorf("unexpected query %q", r.URL.RawQuery)
		}
		_, _ = w.Write(fixture(t))
	}))
	defer srv.Close()

	inner, closeConn, err := modules.NewOSINTFetcher("", 5*time.Second, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer closeConn()
	f := &rewriteFetcher{inner: inner, base: srv.URL + "/"}

	run := newRun(t)
	scope, err := scanScope.FromTarget("example.com", scanScope.ModeDomain, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "recon", false, run, scope)
	res, err := NewWithFetcher(f, fastRetry).Run(context.Background(), runCtx, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != "completed" || hits.Load() != 2 {
		t.Fatalf("status=%q hits=%d, want completed after one retry", res.Status, hits.Load())
	}
	if len(f.asked) != 2 || f.asked[0] != QueryURL("example.com") {
		t.Fatalf("asked = %v", f.asked)
	}

	art, ok := runCtx.GetArtifact("ct_subdomains")
	if !ok {
		t.Fatal("ct_subdomains not published")
	}
	content, _ := os.ReadFile(run.Path(art.Path))
	if want := "api.example.com\ncdn.example.com\ndev.example.com\nexample.com\nstaging.example.com\nwww.example.com\n"; string(content) != want {
		t.Fatalf("published names = %q, want %q", content, want)
	}
	// The out-of-scope name from a shared certificate is audited, not used.
	rej, err := os.ReadFile(run.Path("00_meta", "scope-rejections.jsonl"))
	if err != nil || !strings.Contains(string(rej), "other-tenant.net") {
		t.Fatalf("scope-rejections.jsonl missing other-tenant.net: %q %v", rej, err)
	}
	if scope.IsAllowed("other-tenant.net") {
		t.Fatal("scope was widened by an OSINT discovery")
	}
}

func TestRunExactScopeKeepsOnlyTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(fixture(t)) }))
	defer srv.Close()
	inner, closeConn, _ := modules.NewOSINTFetcher("", 5*time.Second, 1<<20)
	defer closeConn()

	run := newRun(t)
	scope, _ := scanScope.FromTarget("example.com", scanScope.ModeExact, nil, nil)
	runCtx := modules.NewRunContext("example.com", "recon", false, run, scope)
	if _, err := NewWithFetcher(&rewriteFetcher{inner: inner, base: srv.URL + "/"}, fastRetry).Run(context.Background(), runCtx, nil); err != nil {
		t.Fatal(err)
	}
	art, _ := runCtx.GetArtifact("ct_subdomains")
	content, _ := os.ReadFile(run.Path(art.Path))
	if string(content) != "example.com\n" {
		t.Fatalf("exact scope should keep only the target, got %q", content)
	}
	if runCtx.RejectedCount("ct_subdomains") != 6 {
		t.Fatalf("rejected = %d, want 6", runCtx.RejectedCount("ct_subdomains"))
	}
}

func TestRunDryRunRecordsRequestWithoutNetwork(t *testing.T) {
	run := newRun(t)
	runCtx := modules.NewRunContext("example.com", "recon", true, run)
	f := &failingFetcher{t: t}
	res, err := NewWithFetcher(f, fastRetry).Run(context.Background(), runCtx, nil)
	if err != nil || res.Status != "completed" {
		t.Fatalf("dry run: %v %v", res, err)
	}
	log, _ := os.ReadFile(run.CommandsLog)
	if !strings.Contains(string(log), "https://crt.sh/?q=%25.example.com&output=json") {
		t.Fatalf("planned request not in command log: %q", log)
	}
	if _, ok := runCtx.GetArtifact("ct_subdomains"); !ok {
		t.Fatal("artifact must still be published in dry run so the DAG proceeds")
	}
}

type failingFetcher struct{ t *testing.T }

func (f *failingFetcher) Get(context.Context, string) (*modules.FetchResult, error) {
	f.t.Error("network must not be used")
	return nil, context.Canceled
}

func TestRunFailureModes(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		wantErr string
	}{
		{"http error after retries", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "x", http.StatusServiceUnavailable) }, "HTTP 503"},
		{"not found", func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) }, "HTTP 404"},
		{"invalid json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }, "invalid JSON"},
		{"oversized", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(strings.Repeat("a", 4096))) }, "cap"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			inner, closeConn, _ := modules.NewOSINTFetcher("", 5*time.Second, 1024) // tiny cap
			defer closeConn()
			runCtx := modules.NewRunContext("example.com", "recon", false, newRun(t))
			_, err := NewWithFetcher(&rewriteFetcher{inner: inner, base: srv.URL + "/"}, fastRetry).Run(context.Background(), runCtx, nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestRunSkipsIPTarget(t *testing.T) {
	runCtx := modules.NewRunContext("203.0.113.9", "recon", false, newRun(t))
	res, err := NewWithFetcher(&failingFetcher{t: t}, fastRetry).Run(context.Background(), runCtx, nil)
	if err != nil || !modules.IsNotApplicable(res) {
		t.Fatalf("IP target should be skipped: %+v %v", res, err)
	}
}

func TestRunUsesProxy(t *testing.T) {
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Add(1)
		if !strings.Contains(r.URL.String(), "crt.sh") {
			t.Errorf("proxy got %q", r.URL)
		}
		_, _ = w.Write([]byte("[]"))
	}))
	defer proxy.Close()
	runCtx := modules.NewRunContext("example.com", "recon", false, newRun(t))
	runCtx.Proxy = proxy.URL
	// HTTPS through an HTTP proxy would CONNECT; use the plain fetcher
	// against an http URL to prove the proxy is honored.
	f, closeConn, err := modules.NewOSINTFetcher(runCtx.Proxy, 5*time.Second, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer closeConn()
	if _, err := f.Get(context.Background(), "http://crt.sh/?q=x"); err != nil {
		t.Fatal(err)
	}
	if proxied.Load() != 1 {
		t.Fatal("request did not go through the proxy")
	}
}
