package report

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseHosts(t *testing.T) {
	content := "example.com\nhttps://sub.example.com\n"
	path := writeTempFile(t, content)

	rep := NewReport("example.com", "test")
	err := ParseHosts(path, rep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rep.Assets) != 2 {
		t.Fatalf("expected 2 assets, got %d", len(rep.Assets))
	}
	if _, ok := rep.Assets["example.com"]; !ok {
		t.Error("missing example.com")
	}
	if _, ok := rep.Assets["sub.example.com"]; !ok {
		t.Error("missing sub.example.com")
	}
}

func TestParsePorts(t *testing.T) {
	content := "example.com:80\nexample.com:443\nsub.example.com:8080\n"
	path := writeTempFile(t, content)

	rep := NewReport("example.com", "test")
	err := ParsePorts(path, rep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	asset := rep.GetOrCreateAsset("example.com")
	if len(asset.Ports) != 2 {
		t.Fatalf("expected 2 ports on example.com, got %d", len(asset.Ports))
	}
	if asset.Ports[80].Number != 80 {
		t.Error("missing port 80")
	}
}

func TestParseHttpx(t *testing.T) {
	content := `{"url":"https://example.com","host":"example.com","tech":["Nginx","PHP"]}
{"url":"http://example.com","host":"example.com","tech":["Nginx"]}
`
	path := writeTempFile(t, content)

	rep := NewReport("example.com", "test")
	err := ParseHttpx(path, rep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	asset := rep.GetOrCreateAsset("example.com")
	if len(asset.Technologies) != 2 {
		t.Fatalf("expected 2 unique technologies, got %d", len(asset.Technologies))
	}
}

func TestParseFfuf(t *testing.T) {
	content := `{"results":[{"url":"https://example.com/admin","host":"example.com"}]}`
	path := writeTempFile(t, content)

	rep := NewReport("example.com", "test")
	err := ParseFfuf(path, rep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	asset := rep.GetOrCreateAsset("example.com")
	if len(asset.Paths) != 1 || asset.Paths[0] != "https://example.com/admin" {
		t.Error("failed to parse ffuf paths")
	}
}

func TestParseKatana(t *testing.T) {
	content := "https://example.com/login\nhttps://example.com/dashboard\n"
	path := writeTempFile(t, content)

	rep := NewReport("example.com", "test")
	err := ParseKatana(path, rep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	asset := rep.GetOrCreateAsset("example.com")
	if len(asset.Paths) != 2 {
		t.Error("failed to parse katana paths")
	}
}

func TestParseNuclei(t *testing.T) {
	content := `{"template-id":"cve-2021-1234","matched-at":"https://example.com","host":"example.com","info":{"name":"Test CVE","severity":"high"}}`
	path := writeTempFile(t, content)

	rep := NewReport("example.com", "test")
	err := ParseNuclei(path, rep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	asset := rep.GetOrCreateAsset("example.com")
	if len(asset.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(asset.Vulnerabilities))
	}
	
	v := asset.Vulnerabilities[0]
	if v.TemplateID != "cve-2021-1234" || v.Severity != "high" {
		t.Error("invalid nuclei vulnerability parsing")
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
