package scope

import (
	"os"
	"path/filepath"
	"testing"
)

func writeScopeFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write scope file: %v", err)
	}

	return path
}

func TestLoadFromFileExactHost(t *testing.T) {
	path := writeScopeFile(t, "example.com\n")

	s, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !s.IsAllowed("example.com") {
		t.Fatal("expected example.com to be allowed")
	}

	if s.IsAllowed("other.com") {
		t.Fatal("expected other.com to be rejected")
	}
}

func TestLoadFromFileWildcard(t *testing.T) {
	path := writeScopeFile(t, "*.example.com\n")

	s, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !s.IsAllowed("api.example.com") {
		t.Fatal("expected api.example.com to be allowed")
	}

	if s.IsAllowed("example.com") {
		t.Fatal("expected bare example.com to be rejected for *.example.com")
	}
}

func TestLoadFromFileCIDR(t *testing.T) {
	path := writeScopeFile(t, "10.0.0.0/24\n")

	s, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !s.IsAllowed("10.0.0.42") {
		t.Fatal("expected 10.0.0.42 to be allowed")
	}

	if s.IsAllowed("10.0.1.1") {
		t.Fatal("expected 10.0.1.1 to be rejected")
	}
}

func TestNormalizeHostURL(t *testing.T) {
	path := writeScopeFile(t, "example.com\n")

	s, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !s.IsAllowed("https://example.com/path") {
		t.Fatal("expected normalized URL host to be allowed")
	}
}

func TestLoadFromFileCommentsAndEmptyLines(t *testing.T) {
	path := writeScopeFile(t, "# comment\n\nexample.com\n")

	s, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !s.IsAllowed("example.com") {
		t.Fatal("expected example.com to be allowed")
	}
}

func TestIsAllowedEmptyTarget(t *testing.T) {
	s := &Scope{ExactHosts: map[string]struct{}{}}

	if s.IsAllowed("") {
		t.Fatal("expected empty target to be rejected")
	}
}
