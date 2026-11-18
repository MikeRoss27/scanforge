package wpplugins

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

func TestEffectiveDetectionMode(t *testing.T) {
	cases := map[string]string{
		"":           "passive",
		"passive":    "passive",
		"mixed":      "mixed",
		"aggressive": "aggressive",
		" PASSIVE ":  "passive",
	}
	for raw, want := range cases {
		got, err := effectiveDetectionMode(raw)
		if err != nil {
			t.Fatalf("effectiveDetectionMode(%q) error = %v", raw, err)
		}
		if got != want {
			t.Fatalf("effectiveDetectionMode(%q) = %q, want %q", raw, got, want)
		}
	}
	if _, err := effectiveDetectionMode("loud"); err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

func TestScanCrawledArtifactExtractsSlugsAndVersions(t *testing.T) {
	found := map[pluginKey]*Finding{}
	addHit := func(host, slug, version, source, detection, evidence string) {
		found[pluginKey{host, slug}] = &Finding{
			URL: host, Plugin: slug, Version: version,
			Source: source, Detection: detection, Evidence: evidence,
		}
	}
	run := testRun(t)
	writeFile(t, run.Path("03_crawl", "crawled_urls.txt"),
		"https://example.com/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.3.1\n"+
			"https://example.com/wp-content/plugins/elementor/assets/css/frontend.css?ver=3.5.6\n"+
			"https://other.test/wp-content/plugins/woocommerce/assets/js/frontend.js?ver=8.8.0\n"+
			"https://example.com/about\n")

	runCtx := modules.NewRunContext("example.com", "wp", true, run)
	if err := runCtx.AddArtifact("crawled_urls", modules.Artifact{Name: "crawled_urls", Type: "text", Path: "03_crawl/crawled_urls.txt"}); err != nil {
		t.Fatal(err)
	}
	scanCrawledArtifact(runCtx, addHit)

	cf7, ok := found[pluginKey{"https://example.com", "contact-form-7"}]
	if !ok {
		t.Fatal("missing contact-form-7 hit")
	}
	if cf7.Version != "5.3.1" {
		t.Fatalf("contact-form-7 version = %q, want 5.3.1", cf7.Version)
	}
	if cf7.Source != "asset" || cf7.Detection != "passive" {
		t.Fatalf("contact-form-7 source/detection = %q/%q", cf7.Source, cf7.Detection)
	}
	if _, ok := found[pluginKey{"https://example.com", "elementor"}]; !ok {
		t.Fatal("missing elementor hit")
	}
	if _, ok := found[pluginKey{"https://other.test", "woocommerce"}]; !ok {
		t.Fatal("missing woocommerce hit for the external host")
	}
}

func TestRunDryRunPassive(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"00_meta", "02_http", "03_crawl", "04_wordpress", "06_vulns"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(root, "04_wordpress", "wp-fingerprint.jsonl"),
		`{"target":"https://example.com","is_wordpress":true,"core_version":"6.4.2","sources":["generator"],"confidence":"high","fetched_at":"2026-11-18T00:00:00Z"}`+"\n")
	writeFile(t, filepath.Join(root, "03_crawl", "crawled_urls.txt"),
		"https://example.com/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.3.1\n")

	run := &storage.Run{
		RootDir:     root,
		MetaDir:     filepath.Join(root, "00_meta"),
		CommandsLog: filepath.Join(root, "00_meta", "commands.log"),
	}
	runCtx := modules.NewRunContext("example.com", "wp", true, run)
	opt := runCtx.WordPress
	opt.DetectionMode = "passive"
	runCtx.WordPress = opt
	if err := runCtx.AddArtifact("wp_fingerprint", modules.Artifact{Name: "wp_fingerprint", Type: "jsonl", Path: "04_wordpress/wp-fingerprint.jsonl"}); err != nil {
		t.Fatal(err)
	}
	if err := runCtx.AddArtifact("crawled_urls", modules.Artifact{Name: "crawled_urls", Type: "text", Path: "03_crawl/crawled_urls.txt"}); err != nil {
		t.Fatal(err)
	}
	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(root, outputRel))
	if err != nil {
		t.Fatal(err)
	}
	var found []Finding
	for _, line := range splitLines(string(data)) {
		if line == "" {
			continue
		}
		var f Finding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Fatalf("invalid plugin finding JSON: %v", err)
		}
		found = append(found, f)
	}
	if len(found) != 1 || found[0].Plugin != "contact-form-7" || found[0].Version != "5.3.1" {
		t.Fatalf("plugins = %+v, want one contact-form-7 5.3.1 entry", found)
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func testRun(t *testing.T) *storage.Run {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"00_meta", "03_crawl", "04_wordpress", "06_vulns"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return &storage.Run{
		RootDir:     root,
		MetaDir:     filepath.Join(root, "00_meta"),
		CommandsLog: filepath.Join(root, "00_meta", "commands.log"),
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
