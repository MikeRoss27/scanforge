package wpthemes

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
	"github.com/MikeRoss27/scanforge/internal/modules/wpcore"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

func TestScanCrawledArtifactExtractsSlugsAndVersions(t *testing.T) {
	found := map[themeKey]*Finding{}
	addHit := func(host, slug, version, source, detection, evidence string) {
		found[themeKey{host, slug}] = &Finding{
			URL: host, Theme: slug, Version: version,
			Source: source, Detection: detection, Evidence: evidence,
		}
	}
	run := testRun(t)
	writeFile(t, run.Path("03_crawl", "crawled_urls.txt"),
		"https://example.com/wp-content/themes/astra/assets/css/style.min.css?ver=4.6.1\n"+
			"https://example.com/wp-content/themes/twentytwentyone/style.css?ver=1.7\n"+
			"https://other.test/wp-content/themes/divi/images/logo.png?ver=4.21.0\n"+
			"https://example.com/about\n")

	runCtx := modules.NewRunContext("example.com", "wp", true, run)
	if err := runCtx.AddArtifact("crawled_urls", modules.Artifact{Name: "crawled_urls", Type: "text", Path: "03_crawl/crawled_urls.txt"}); err != nil {
		t.Fatal(err)
	}
	scanCrawledArtifact(runCtx, addHit)

	astra, ok := found[themeKey{"https://example.com", "astra"}]
	if !ok {
		t.Fatal("missing astra hit")
	}
	if astra.Version != "4.6.1" {
		t.Fatalf("astra version = %q, want 4.6.1", astra.Version)
	}
	if astra.Source != "asset" || astra.Detection != "passive" {
		t.Fatalf("astra source/detection = %q/%q", astra.Source, astra.Detection)
	}
	if _, ok := found[themeKey{"https://example.com", "twentytwentyone"}]; !ok {
		t.Fatal("missing twentytwentyone hit")
	}
	if _, ok := found[themeKey{"https://other.test", "divi"}]; !ok {
		t.Fatal("missing divi hit for the external host")
	}
}

func TestSlugsToProbeRespectsMode(t *testing.T) {
	found := map[themeKey]*Finding{{"https://example.com", "astra"}: {}}
	runCtx := modules.NewRunContext("example.com", "wp", true, &storage.Run{RootDir: t.TempDir()})

	if slugs := slugsToProbe(runCtx, "passive", found); slugs != nil {
		t.Fatalf("passive mode must never probe, got %v", slugs)
	}

	mixed := slugsToProbe(runCtx, "mixed", found)
	if len(mixed) != 1 || mixed[0] != "astra" {
		t.Fatalf("mixed mode = %v, want only the passively-found slug [astra]", mixed)
	}

	aggressive := slugsToProbe(runCtx, "aggressive", found)
	if len(aggressive) < len(mixed) {
		t.Fatalf("aggressive mode should probe at least the mixed-mode slugs plus the wordlist, got %v", aggressive)
	}
	hasAstra := false
	for _, s := range aggressive {
		if s == "astra" {
			hasAstra = true
		}
	}
	if !hasAstra {
		t.Fatalf("aggressive mode dropped the passively-found slug: %v", aggressive)
	}
}

func TestLoadWordlistFiltersInvalidSlugsAndDedupes(t *testing.T) {
	bundled := []byte("astra\nASTRA\n!not-a-slug\n\nx\ngood-slug\n")
	got := loadWordlist("", bundled)
	want := []string{"astra", "good-slug"}
	if len(got) != len(want) {
		t.Fatalf("loadWordlist = %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("loadWordlist[%d] = %q, want %q (got %v)", i, got[i], w, got)
		}
	}
}

func TestLoadWordlistFallsBackToBundledWhenPathUnreadable(t *testing.T) {
	bundled := []byte("fallback-slug\n")
	got := loadWordlist(filepath.Join(t.TempDir(), "does-not-exist.txt"), bundled)
	if len(got) != 1 || got[0] != "fallback-slug" {
		t.Fatalf("loadWordlist with an unreadable path = %v, want the bundled list", got)
	}
}

func TestRunDryRunPassive(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"00_meta", "02_http", "03_crawl", wpcore.OutputDir, "06_vulns"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(root, wpcore.OutputDir, "wp-fingerprint.jsonl"),
		`{"target":"https://example.com","is_wordpress":true,"core_version":"6.4.2","sources":["generator"],"confidence":"high","fetched_at":"2026-11-18T00:00:00Z"}`+"\n")
	writeFile(t, filepath.Join(root, "03_crawl", "crawled_urls.txt"),
		"https://example.com/wp-content/themes/astra/style.css?ver=4.6.1\n")

	run := &storage.Run{
		RootDir:     root,
		MetaDir:     filepath.Join(root, "00_meta"),
		CommandsLog: filepath.Join(root, "00_meta", "commands.log"),
	}
	runCtx := modules.NewRunContext("example.com", "wp", true, run)
	opt := runCtx.WordPress
	opt.DetectionMode = "passive"
	runCtx.WordPress = opt
	if err := runCtx.AddArtifact("wp_fingerprint", modules.Artifact{Name: "wp_fingerprint", Type: "jsonl", Path: wpcore.OutputDir + "/wp-fingerprint.jsonl"}); err != nil {
		t.Fatal(err)
	}
	if err := runCtx.AddArtifact("crawled_urls", modules.Artifact{Name: "crawled_urls", Type: "text", Path: "03_crawl/crawled_urls.txt"}); err != nil {
		t.Fatal(err)
	}
	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	found := readFindings(t, run)
	if len(found) != 1 || found[0].Theme != "astra" || found[0].Version != "4.6.1" {
		t.Fatalf("themes = %+v, want one astra 4.6.1 entry", found)
	}
}

func TestRunAggressiveModeProbesStyleCSSForVersion(t *testing.T) {
	var mux http.ServeMux
	mux.HandleFunc("/wp-content/themes/astra/style.css", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("/*\nTheme Name: Astra\nVersion: 4.6.1\n*/"))
	})
	// Soft-404: 200 but no "theme" marker and no Version header.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>not found</html>"))
	})
	server := httptest.NewServer(&mux)
	defer server.Close()

	root := t.TempDir()
	for _, dir := range []string{"00_meta", wpcore.OutputDir, "06_vulns"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	run := &storage.Run{
		RootDir:     root,
		MetaDir:     filepath.Join(root, "00_meta"),
		CommandsLog: filepath.Join(root, "00_meta", "commands.log"),
	}
	writeFile(t, filepath.Join(root, wpcore.OutputDir, "wp-fingerprint.jsonl"),
		marshalFingerprint(t, server.URL)+"\n")

	runCtx := modules.NewRunContext("example.com", "wp", false, run)
	opt := runCtx.WordPress
	opt.DetectionMode = "aggressive"
	opt.Wordlist = writeTempWordlist(t, "astra\nnonexistent-theme\n")
	runCtx.WordPress = opt
	if err := runCtx.AddArtifact("wp_fingerprint", modules.Artifact{Name: "wp_fingerprint", Type: "jsonl", Path: wpcore.OutputDir + "/wp-fingerprint.jsonl"}); err != nil {
		t.Fatal(err)
	}

	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	found := readFindings(t, run)
	if len(found) != 1 {
		t.Fatalf("got %d findings, want exactly 1 (nonexistent-theme must not match the soft-404): %+v", len(found), found)
	}
	if found[0].Theme != "astra" || found[0].Version != "4.6.1" || found[0].Source != "style.css" {
		t.Fatalf("finding = %+v, want astra 4.6.1 via style.css", found[0])
	}
	if found[0].Confidence != "high" {
		t.Errorf("confidence = %q, want high for a style.css-confirmed version", found[0].Confidence)
	}
}

// writeTempWordlist is the aggressive-mode --wp-wordlist override; mixed
// mode never reads it (only passively-found slugs), aggressive mode does.
func writeTempWordlist(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "themes.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func marshalFingerprint(t *testing.T, target string) string {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"target": target, "is_wordpress": true, "core_version": "6.4.2",
		"sources": []string{"generator"}, "confidence": "high", "fetched_at": "2026-11-18T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func testRun(t *testing.T) *storage.Run {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"00_meta", "03_crawl", wpcore.OutputDir, "06_vulns"} {
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

func readFindings(t *testing.T, run *storage.Run) []Finding {
	t.Helper()
	data, err := os.ReadFile(run.Path(outputRel))
	if err != nil {
		t.Fatal(err)
	}
	var found []Finding
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var f Finding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Fatalf("invalid wp_themes finding JSON: %v", err)
		}
		found = append(found, f)
	}
	return found
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
