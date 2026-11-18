package wpdetect

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

const wpHomepage = `<html><head>
<meta name="generator" content="WordPress 6.4.2" />
</head><body><a href="/wp-content/themes/x/style.css">theme</a></body></html>`

const wpReadme = `<html><head><title>WordPress</title></head><body><h1>ABOUT WORDPRESS</h1><p>Version 6.4.2</p></body></html>`

const wpFeed = `<?xml version="1.0"?><rss><channel><generator>https://wordpress.org/?v=6.4.2</generator></channel></rss>`

const wpJSON = `{"name":"Example","namespaces":["oembed/1.0","wp/v2"]}`

func TestProbeHostDetectsWordPress(t *testing.T) {
	var mux http.ServeMux
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery == "feed=rss2" {
			io.WriteString(w, wpFeed)
			return
		}
		io.WriteString(w, wpHomepage)
	})
	mux.HandleFunc("/readme.html", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, wpReadme)
	})
	mux.HandleFunc("/wp-json/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, wpJSON)
	})
	server := httptest.NewServer(&mux)
	defer server.Close()

	runCtx := testRunContext(t, server.URL)
	result := probeHost(context.Background(), server.Client(), runCtx, server.URL)
	if !result.IsWordPress {
		t.Fatalf("expected WordPress detection on %s", server.URL)
	}
	if result.CoreVersion != "6.4.2" {
		t.Fatalf("CoreVersion = %q, want 6.4.2", result.CoreVersion)
	}
	if result.Confidence != "high" {
		t.Fatalf("Confidence = %q, want high (sources=%v)", result.Confidence, result.Sources)
	}
	if len(result.Sources) < 2 {
		t.Fatalf("expected multiple detection sources, got %v", result.Sources)
	}
}

func TestProbeHostIgnoresNonWordPress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<html><head><title>static</title></head><body>plain site</body></html>")
	}))
	defer server.Close()

	runCtx := testRunContext(t, server.URL)
	result := probeHost(context.Background(), server.Client(), runCtx, server.URL)
	if result.IsWordPress {
		t.Fatalf("unexpected WordPress detection on %s", server.URL)
	}
}

func TestRunDryRunPublishesArtifact(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"00_meta", "02_http", "04_wordpress"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "02_http/alive_urls.txt"), []byte("https://example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := &storage.Run{
		RootDir:     root,
		MetaDir:     filepath.Join(root, "00_meta"),
		CommandsLog: filepath.Join(root, "00_meta", "commands.log"),
	}
	runCtx := modules.NewRunContext("example.com", "wp", true, run)
	if err := runCtx.AddArtifact("alive_urls", modules.Artifact{Name: "alive_urls", Type: "text", Path: "02_http/alive_urls.txt"}); err != nil {
		t.Fatal(err)
	}
	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if _, ok := runCtx.GetArtifact("wp_fingerprint"); !ok {
		t.Fatal("wp_fingerprint artifact was not published")
	}

	data, err := os.ReadFile(run.Path(fingerprintFile))
	if err != nil {
		t.Fatal(err)
	}
	var record Finding
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &record); err != nil {
		t.Fatalf("invalid fingerprint JSON: %v", err)
	}
	if record.Target != "https://example.com" {
		t.Fatalf("Target = %q, want https://example.com", record.Target)
	}
	if record.IsWordPress {
		t.Fatal("dry-run must not claim WordPress detection")
	}
}

func testRunContext(t *testing.T, baseURL string) *modules.RunContext {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"00_meta"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	run := &storage.Run{
		RootDir:     root,
		MetaDir:     filepath.Join(root, "00_meta"),
		CommandsLog: filepath.Join(root, "00_meta", "commands.log"),
	}
	_ = baseURL
	return modules.NewRunContext("example.com", "wp", false, run)
}
