package wpexposure

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

func TestValidateChecksAcceptsTheRealTable(t *testing.T) {
	if err := validateChecks(); err != nil {
		t.Fatalf("the shipped exposureChecks table is invalid: %v", err)
	}
}

func TestRunFindsMatchingExposuresOnly(t *testing.T) {
	var mux http.ServeMux
	// A real exposed wp-config backup: 200 + the marker substring.
	mux.HandleFunc("/wp-config.php.bak", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("define('DB_PASSWORD', 'secret');"))
	})
	// 200 but the body never mentions the marker: looks like a generic
	// catch-all page, must not be reported as an exposure.
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>not found, sorry</html>"))
	})
	// A genuine 404 for everything else, including every other check path.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	server := httptest.NewServer(&mux)
	defer server.Close()

	run := testRun(t)
	writeFPFile(t, run, server.URL)
	runCtx := modules.NewRunContext("example.com", "wp", false, run)
	if err := runCtx.AddArtifact("wp_fingerprint", modules.Artifact{Name: "wp_fingerprint", Type: "jsonl", Path: wpcore.OutputDir + "/wp-fingerprint.jsonl"}); err != nil {
		t.Fatal(err)
	}

	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	found := readFindings(t, run)
	if len(found) != 1 {
		t.Fatalf("got %d findings, want exactly 1 (the real backup): %+v", len(found), found)
	}
	if found[0].Check != "wp-config-backup" || found[0].Severity != "critical" {
		t.Errorf("finding = %+v, want the wp-config-backup/critical check", found[0])
	}
	if !strings.HasSuffix(found[0].URL, "/wp-config.php.bak") {
		t.Errorf("finding URL = %q, want it to end with /wp-config.php.bak", found[0].URL)
	}
}

func TestRunMatchesEitherMarkerInAnOrList(t *testing.T) {
	// debug-log's marker is an OR list: "fatal error|stack trace|uncaught|...".
	// Only one of them needs to appear.
	var mux http.ServeMux
	mux.HandleFunc("/wp-content/debug.log", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("PHP Stack trace:\n#0 {main}"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	server := httptest.NewServer(&mux)
	defer server.Close()

	run := testRun(t)
	writeFPFile(t, run, server.URL)
	runCtx := modules.NewRunContext("example.com", "wp", false, run)
	if err := runCtx.AddArtifact("wp_fingerprint", modules.Artifact{Name: "wp_fingerprint", Type: "jsonl", Path: wpcore.OutputDir + "/wp-fingerprint.jsonl"}); err != nil {
		t.Fatal(err)
	}

	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	found := readFindings(t, run)
	if len(found) != 1 || found[0].Check != "debug-log" {
		t.Fatalf("findings = %+v, want exactly one debug-log hit", found)
	}
}

func TestRunNoWordPressHostsSkipsProbing(t *testing.T) {
	run := testRun(t)
	writeFile(t, run.Path(wpcore.OutputDir, "wp-fingerprint.jsonl"), "")
	runCtx := modules.NewRunContext("example.com", "wp", false, run)
	if err := runCtx.AddArtifact("wp_fingerprint", modules.Artifact{Name: "wp_fingerprint", Type: "jsonl", Path: wpcore.OutputDir + "/wp-fingerprint.jsonl"}); err != nil {
		t.Fatal(err)
	}

	result, err := New().Run(context.Background(), runCtx, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "skipped" || result.Reason != "no WordPress detected" {
		t.Fatalf("status = %q reason = %q, want skipped/no WordPress detected", result.Status, result.Reason)
	}
	if found := readFindings(t, run); len(found) != 0 {
		t.Fatalf("expected no findings with no WordPress hosts, got %+v", found)
	}
}

func TestRunDryRunMakesNoRequests(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	run := testRun(t)
	writeFPFile(t, run, server.URL)
	runCtx := modules.NewRunContext("example.com", "wp", true, run)
	if err := runCtx.AddArtifact("wp_fingerprint", modules.Artifact{Name: "wp_fingerprint", Type: "jsonl", Path: wpcore.OutputDir + "/wp-fingerprint.jsonl"}); err != nil {
		t.Fatal(err)
	}

	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if called {
		t.Fatal("dry run must not contact the target")
	}
	if _, ok := runCtx.GetArtifact(reportName); !ok {
		t.Fatal("wp_exposure artifact was not published on a dry run")
	}
}

func testRun(t *testing.T) *storage.Run {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"00_meta", wpcore.OutputDir} {
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

func writeFPFile(t *testing.T, run *storage.Run, target string) {
	t.Helper()
	record := map[string]any{
		"target": target, "is_wordpress": true, "core_version": "6.4.2",
		"sources": []string{"generator"}, "confidence": "high", "fetched_at": "2026-11-18T00:00:00Z",
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, run.Path(wpcore.OutputDir, "wp-fingerprint.jsonl"), string(data)+"\n")
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
			t.Fatalf("invalid wp_exposure finding JSON: %v", err)
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
