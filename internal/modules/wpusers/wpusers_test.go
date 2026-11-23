package wpusers

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
	"github.com/MikeRoss27/scanforge/internal/storage"
)

func TestRunEnumeratesUsersFromRedirectsAndREST(t *testing.T) {
	var mux http.ServeMux
	// ?author=1 redirects to /author/admin — the classic wpscan probe.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("author") {
		case "1":
			http.Redirect(w, r, "/author/admin", http.StatusMovedPermanently)
		default:
			w.WriteHeader(http.StatusOK)
		}
	})
	// The REST API exposes a second user that no ?author=N probe reached,
	// plus a display name to merge onto the already-found admin.
	mux.HandleFunc("/wp-json/wp/v2/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"id":1,"name":"Site Admin","slug":"admin","link":"https://x/author/admin"},
			{"id":2,"name":"Jane Editor","slug":"jane","link":"https://x/author/jane"}
		]`))
	})
	server := httptest.NewServer(&mux)
	defer server.Close()

	run := testRun(t)
	writeFPFile(t, run, server.URL)
	runCtx := modules.NewRunContext("example.com", "wp", false, run)
	if err := runCtx.AddArtifact("wp_fingerprint", modules.Artifact{Name: "wp_fingerprint", Type: "jsonl", Path: fpFile}); err != nil {
		t.Fatal(err)
	}

	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	found := readFindings(t, run)
	byLogin := map[string]Finding{}
	for _, f := range found {
		byLogin[f.Login] = f
	}

	admin, ok := byLogin["admin"]
	if !ok {
		t.Fatalf("missing admin user, got %+v", found)
	}
	if admin.Source != "author-redirect" {
		t.Errorf("admin.Source = %q, want author-redirect (first probe to find it wins)", admin.Source)
	}
	if admin.DisplayName != "Site Admin" {
		t.Errorf("admin.DisplayName = %q, want REST to have merged it onto the redirect hit", admin.DisplayName)
	}

	jane, ok := byLogin["jane"]
	if !ok {
		t.Fatalf("missing jane user (REST-only hit), got %+v", found)
	}
	if jane.Source != "rest-api" {
		t.Errorf("jane.Source = %q, want rest-api", jane.Source)
	}
}

func TestRunDeduplicatesSameLoginAcrossProbes(t *testing.T) {
	var mux http.ServeMux
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("author") == "1" {
			http.Redirect(w, r, "/author/admin", http.StatusMovedPermanently)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/wp-json/wp/v2/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":1,"name":"Site Admin","slug":"admin","link":"https://x/author/admin"}]`))
	})
	server := httptest.NewServer(&mux)
	defer server.Close()

	run := testRun(t)
	writeFPFile(t, run, server.URL)
	runCtx := modules.NewRunContext("example.com", "wp", false, run)
	if err := runCtx.AddArtifact("wp_fingerprint", modules.Artifact{Name: "wp_fingerprint", Type: "jsonl", Path: fpFile}); err != nil {
		t.Fatal(err)
	}

	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	found := readFindings(t, run)
	if len(found) != 1 {
		t.Fatalf("got %d findings for the same login seen twice, want 1: %+v", len(found), found)
	}
}

func TestRunNoWordPressHostsSkipsProbing(t *testing.T) {
	run := testRun(t)
	writeFile(t, run.Path(fpFile), "") // empty fingerprint: nothing identified as WordPress
	runCtx := modules.NewRunContext("example.com", "wp", false, run)
	if err := runCtx.AddArtifact("wp_fingerprint", modules.Artifact{Name: "wp_fingerprint", Type: "jsonl", Path: fpFile}); err != nil {
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
	if err := runCtx.AddArtifact("wp_fingerprint", modules.Artifact{Name: "wp_fingerprint", Type: "jsonl", Path: fpFile}); err != nil {
		t.Fatal(err)
	}

	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if called {
		t.Fatal("dry run must not contact the target")
	}
	if _, ok := runCtx.GetArtifact(reportName); !ok {
		t.Fatal("wp_users artifact was not published on a dry run")
	}
}

func testRun(t *testing.T) *storage.Run {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"00_meta", wpcoreOutputDir()} {
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

// wpcoreOutputDir avoids importing wpcore just for its OutputDir constant in
// the test's directory-setup helper (fpFile/outputRel already carry it).
func wpcoreOutputDir() string {
	return filepath.Dir(fpFile)
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
	writeFile(t, run.Path(fpFile), string(data)+"\n")
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
			t.Fatalf("invalid wp_users finding JSON: %v", err)
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
