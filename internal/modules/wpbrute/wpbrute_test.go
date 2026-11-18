package wpbrute

import (
	"context"
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
