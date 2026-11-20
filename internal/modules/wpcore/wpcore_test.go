package wpcore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFingerprintKeepsOnlyWordPressHosts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wp-fingerprint.jsonl")
	content := `{"target":"https://wp.example.com","is_wordpress":true,"core_version":"6.4.2","sources":["generator"],"confidence":"high","fetched_at":"2026-11-18T00:00:00Z"}
{"target":"https://plain.example.com","is_wordpress":false,"sources":[],"confidence":"low","fetched_at":"2026-11-18T00:00:00Z"}
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	hosts, err := LoadFingerprint(path)
	if err != nil {
		t.Fatalf("LoadFingerprint() error = %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts, want 1 (non-WordPress host must be dropped): %+v", len(hosts), hosts)
	}
	if hosts[0].Target != "https://wp.example.com" || hosts[0].CoreVersion != "6.4.2" {
		t.Fatalf("host = %+v, want the WordPress one with its version", hosts[0])
	}
}

func TestLoadFingerprintSkipsMalformedLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wp-fingerprint.jsonl")
	content := "not json at all\n" +
		`{"target":"https://wp.example.com","is_wordpress":true,"sources":["generator"],"confidence":"high","fetched_at":"2026-11-18T00:00:00Z"}` + "\n" +
		"\n" // trailing blank line must not become a zero-value record
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	hosts, err := LoadFingerprint(path)
	if err != nil {
		t.Fatalf("LoadFingerprint() error = %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts, want 1 (malformed/blank lines must be skipped, not error): %+v", len(hosts), hosts)
	}
}

func TestLoadFingerprintMissingFileReturnsNoError(t *testing.T) {
	hosts, err := LoadFingerprint(filepath.Join(t.TempDir(), "does-not-exist.jsonl"))
	if err != nil {
		t.Fatalf("LoadFingerprint() on a missing file should not error (modules run before wpdetect produces anything), got %v", err)
	}
	if hosts != nil {
		t.Fatalf("hosts = %+v, want nil for a missing file", hosts)
	}
}
