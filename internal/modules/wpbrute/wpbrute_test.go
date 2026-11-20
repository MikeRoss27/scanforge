package wpbrute

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

func TestBruteforceDisabledIsSkipped(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"00_meta", "04_wordpress", "06_vulns"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(root, "04_wordpress", "wp-fingerprint.jsonl"),
		`{"target":"https://example.com","is_wordpress":true,"core_version":"6.4.2","sources":["generator"],"confidence":"high","fetched_at":"2026-11-18T00:00:00Z"}`+"\n")

	run := &storage.Run{
		RootDir:     root,
		MetaDir:     filepath.Join(root, "00_meta"),
		CommandsLog: filepath.Join(root, "00_meta", "commands.log"),
	}
	runCtx := modules.NewRunContext("example.com", "wp", true, run)
	if err := runCtx.AddArtifact("wp_fingerprint", modules.Artifact{Name: "wp_fingerprint", Type: "jsonl", Path: "04_wordpress/wp-fingerprint.jsonl"}); err != nil {
		t.Fatal(err)
	}

	result, err := New().Run(context.Background(), runCtx, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "skipped" {
		t.Fatalf("status = %q, want skipped", result.Status)
	}
}

func TestBruteforceRequiresPasswordsFile(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"00_meta", "04_wordpress", "06_vulns"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(root, "04_wordpress", "wp-fingerprint.jsonl"),
		`{"target":"https://example.com","is_wordpress":true,"core_version":"6.4.2","sources":["generator"],"confidence":"high","fetched_at":"2026-11-18T00:00:00Z"}`+"\n")
	writeFile(t, filepath.Join(root, "04_wordpress", "wp-users.jsonl"),
		`{"url":"https://example.com","login":"admin","source":"rest-api","confidence":"high"}`+"\n")

	run := &storage.Run{
		RootDir:     root,
		MetaDir:     filepath.Join(root, "00_meta"),
		CommandsLog: filepath.Join(root, "00_meta", "commands.log"),
	}
	runCtx := modules.NewRunContext("example.com", "wp", true, run)
	opts := runCtx.WordPress
	opts.Bruteforce = true
	opts.PasswordsFile = "" // explicitly missing: must refuse
	runCtx.WordPress = opts
	if err := runCtx.AddArtifact("wp_fingerprint", modules.Artifact{Name: "wp_fingerprint", Type: "jsonl", Path: "04_wordpress/wp-fingerprint.jsonl"}); err != nil {
		t.Fatal(err)
	}

	if _, err := New().Run(context.Background(), runCtx, nil); err == nil {
		t.Fatal("expected refusal when --wp-passwords is missing")
	} else if !strings.Contains(err.Error(), "--wp-passwords") {
		t.Fatalf("error = %v, want it to mention --wp-passwords", err)
	}
}

func TestBruteforceRefusesWithoutEnumeratedUsers(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"00_meta", "04_wordpress", "06_vulns"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(root, "04_wordpress", "wp-fingerprint.jsonl"),
		`{"target":"https://example.com","is_wordpress":true,"core_version":"6.4.2","sources":["generator"],"confidence":"high","fetched_at":"2026-11-18T00:00:00Z"}`+"\n")
	// wp-users.jsonl is intentionally missing an enumerated list.
	writeFile(t, filepath.Join(root, "04_wordpress", "wp-users.jsonl"), "")
	writeFile(t, filepath.Join(root, "passwords.txt"), "hunter2\npassword\n")

	run := &storage.Run{
		RootDir:     root,
		MetaDir:     filepath.Join(root, "00_meta"),
		CommandsLog: filepath.Join(root, "00_meta", "commands.log"),
	}
	runCtx := modules.NewRunContext("example.com", "wp", true, run)
	opts := runCtx.WordPress
	opts.Bruteforce = true
	opts.PasswordsFile = filepath.Join(root, "passwords.txt")
	runCtx.WordPress = opts
	if err := runCtx.AddArtifact("wp_fingerprint", modules.Artifact{Name: "wp_fingerprint", Type: "jsonl", Path: "04_wordpress/wp-fingerprint.jsonl"}); err != nil {
		t.Fatal(err)
	}
	if err := runCtx.AddArtifact("wp_users", modules.Artifact{Name: "wp_users", Type: "jsonl", Path: "04_wordpress/wp-users.jsonl"}); err != nil {
		t.Fatal(err)
	}

	if _, err := New().Run(context.Background(), runCtx, nil); err == nil {
		t.Fatal("expected refusal when no usernames were enumerated")
	} else if !strings.Contains(err.Error(), "username") {
		t.Fatalf("error = %v, want it to mention usernames", err)
	}
}

func TestLoadWordlist(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "passwords.txt")
	writeFile(t, path, "hunter2\n\npassword\nhunter2\ncustom pass\n")

	passwords, err := loadWordlist(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"hunter2", "password", "custom pass"}
	if len(passwords) != len(want) {
		t.Fatalf("passwords = %v, want %v", passwords, want)
	}
	for i, p := range want {
		if passwords[i] != p {
			t.Fatalf("passwords[%d] = %q, want %q", i, passwords[i], p)
		}
	}
}

// bruteTestRun builds a run directory (under root) with wp_fingerprint
// (pointing at server) and wp_users (one login) already published, ready
// for a Bruteforce=true / PasswordsFile-set Run().
func bruteTestRun(t *testing.T, root string, server *httptest.Server, login string) *modules.RunContext {
	t.Helper()
	for _, dir := range []string{"00_meta", "04_wordpress", "06_vulns"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(root, "04_wordpress", "wp-fingerprint.jsonl"),
		marshalLine(t, map[string]any{"target": server.URL, "is_wordpress": true, "core_version": "6.4.2", "sources": []string{"generator"}, "confidence": "high", "fetched_at": "2026-11-18T00:00:00Z"}))
	writeFile(t, filepath.Join(root, "04_wordpress", "wp-users.jsonl"),
		marshalLine(t, map[string]any{"url": server.URL, "login": login, "source": "rest-api", "confidence": "high"}))

	run := &storage.Run{
		RootDir:     root,
		MetaDir:     filepath.Join(root, "00_meta"),
		CommandsLog: filepath.Join(root, "00_meta", "commands.log"),
	}
	runCtx := modules.NewRunContext("example.com", "wp", false, run)
	if err := runCtx.AddArtifact("wp_fingerprint", modules.Artifact{Name: "wp_fingerprint", Type: "jsonl", Path: "04_wordpress/wp-fingerprint.jsonl"}); err != nil {
		t.Fatal(err)
	}
	if err := runCtx.AddArtifact("wp_users", modules.Artifact{Name: "wp_users", Type: "jsonl", Path: "04_wordpress/wp-users.jsonl"}); err != nil {
		t.Fatal(err)
	}
	return runCtx
}

func marshalLine(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(data) + "\n"
}

func readBruteFindings(t *testing.T, run *storage.Run) []Finding {
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
			t.Fatalf("invalid wp_brute finding JSON: %v", err)
		}
		found = append(found, f)
	}
	return found
}

func TestRunFindsValidCredentialAndStopsEarly(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if r.FormValue("pwd") == "correct-pass" {
			http.SetCookie(w, &http.Cookie{Name: "wordpress_logged_in_abc123", Value: "1"})
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>login failed</html>"))
	}))
	defer server.Close()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "passwords.txt"), "wrong1\nwrong2\ncorrect-pass\nwrong3\n")
	runCtx := bruteTestRun(t, root, server, "admin")
	run := runCtx.Run
	opts := runCtx.WordPress
	opts.Bruteforce = true
	opts.PasswordsFile = filepath.Join(root, "passwords.txt")
	runCtx.WordPress = opts

	result, err := New().Run(context.Background(), runCtx, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("status = %q, want completed", result.Status)
	}

	found := readBruteFindings(t, run)
	if len(found) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(found), found)
	}
	if !found[0].Success {
		t.Fatalf("finding not marked successful: %+v", found[0])
	}
	if found[0].Attempts != 3 {
		t.Fatalf("Attempts = %d, want 3 (stopped at the correct password, never tried wrong3)", found[0].Attempts)
	}
	if attempts != 3 {
		t.Fatalf("server saw %d requests, want 3 (must stop immediately on success)", attempts)
	}
}

func TestRunStopsOnLockoutMidAttempts(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls >= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "passwords.txt"), "wrong1\nwrong2\nwrong3\nwrong4\n")
	runCtx := bruteTestRun(t, root, server, "admin")
	run := runCtx.Run
	opts := runCtx.WordPress
	opts.Bruteforce = true
	opts.PasswordsFile = filepath.Join(root, "passwords.txt")
	runCtx.WordPress = opts

	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	found := readBruteFindings(t, run)
	if len(found) != 1 || !found[0].LockoutDetected || found[0].Success {
		t.Fatalf("finding = %+v, want a single non-successful lockout record", found)
	}
	if found[0].Attempts != 2 {
		t.Fatalf("Attempts = %d, want 2 (stopped as soon as the lockout appeared)", found[0].Attempts)
	}
	if calls != 2 {
		t.Fatalf("server saw %d requests, want exactly 2 (must stop immediately on lockout, never try wrong3/wrong4)", calls)
	}
}

func TestRunNeverExceedsBruteMax(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK) // never succeeds, never locks out
	}))
	defer server.Close()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "passwords.txt"), "w1\nw2\nw3\nw4\nw5\n")
	runCtx := bruteTestRun(t, root, server, "admin")
	run := runCtx.Run
	opts := runCtx.WordPress
	opts.Bruteforce = true
	opts.PasswordsFile = filepath.Join(root, "passwords.txt")
	opts.BruteMax = 2
	runCtx.WordPress = opts

	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	found := readBruteFindings(t, run)
	if len(found) != 1 || found[0].Attempts != 2 {
		t.Fatalf("finding = %+v, want Attempts capped at BruteMax=2", found)
	}
	if calls != 2 {
		t.Fatalf("server saw %d requests, want exactly 2 (BruteMax must be a hard cap)", calls)
	}
}

func TestRunDryRunMakesNoRequestsAndEmitsWarnings(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "passwords.txt"), "wrong1\nwrong2\n")
	runCtx := bruteTestRun(t, root, server, "admin")
	run := runCtx.Run
	runCtx.DryRun = true
	opts := runCtx.WordPress
	opts.Bruteforce = true
	opts.PasswordsFile = filepath.Join(root, "passwords.txt")
	runCtx.WordPress = opts

	result, err := New().Run(context.Background(), runCtx, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("status = %q, want completed", result.Status)
	}
	if called {
		t.Fatal("dry run must never contact the target")
	}
	if found := readBruteFindings(t, run); len(found) != 0 {
		t.Fatalf("dry run must not record findings, got %+v", found)
	}
}

func TestLockoutDetected(t *testing.T) {
	if !lockoutDetected(429, []byte("nope")) {
		t.Fatal("HTTP 429 must be treated as a lockout")
	}
	if !lockoutDetected(200, []byte("ERROR: The site is temporarily locked out for too many failed logins")) {
		t.Fatal("lockout phrases must be detected")
	}
	if lockoutDetected(302, []byte("")) {
		t.Fatal("302 is not a lockout")
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
