package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MikeRoss27/scanforge/internal/storage"
)

func TestGenerateReport(t *testing.T) {
	dir := t.TempDir()

	// Write dummy files
	if err := os.WriteFile(filepath.Join(dir, "subfinder.txt"), []byte("example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "naabu.txt"), []byte("example.com:80\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "httpx.jsonl"), []byte(`{"url":"http://example.com","host":"example.com","tech":["Nginx"]}`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nuclei.jsonl"), []byte(`{"template-id":"test-cve","matched-at":"example.com","host":"example.com","info":{"name":"Test","severity":"high"}}`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	manifest := &storage.RunManifest{
		Target:      "example.com",
		Profile:     "web",
		StartedAt:   time.Now().Format(time.RFC3339),
		CompletedAt: time.Now().Format(time.RFC3339),
		Status:      "completed",
		Outputs: map[string]string{
			"subfinder":  "subfinder.txt",
			"open_ports": "naabu.txt",
			"httpx_raw":  "httpx.jsonl",
			"nuclei_raw": "nuclei.jsonl",
		},
	}

	rep, err := GenerateReport(dir, manifest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rep.Target != "example.com" {
		t.Errorf("expected target example.com, got %s", rep.Target)
	}
	if len(rep.Assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(rep.Assets))
	}

	asset := rep.Assets["example.com"]
	if len(asset.Ports) != 1 {
		t.Errorf("missing port")
	}
	if len(asset.Technologies) != 1 || asset.Technologies[0] != "Nginx" {
		t.Errorf("missing tech")
	}
	if len(asset.Vulnerabilities) != 1 {
		t.Errorf("missing vuln")
	}
}

// TestGenerateReportBestEffort: one corrupt artifact warns but the rest of
// the report is still produced — a bad file must never discard everything.
func TestGenerateReportBestEffort(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "subfinder.txt"), []byte("example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// A single oversized line trips the scanner buffer limit, which the
	// parsers surface as an error.
	longLine := strings.Repeat("x", 5*1024*1024)
	if err := os.WriteFile(filepath.Join(dir, "nuclei.jsonl"), []byte(longLine+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	manifest := &storage.RunManifest{
		Target: "example.com",
		Status: "completed",
		Outputs: map[string]string{
			"subfinder":  "subfinder.txt",
			"nuclei_raw": "nuclei.jsonl",
		},
	}

	rep, err := GenerateReport(dir, manifest)
	if err == nil {
		t.Fatal("expected a warning for the oversized artifact")
	}
	if len(rep.Assets) != 1 {
		t.Fatalf("expected the host asset to survive the broken nuclei output, got %d assets", len(rep.Assets))
	}
}

// TestGenerateReportRejectsTraversal: manifest paths outside the run
// directory must be refused and never read.
func TestGenerateReportRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(secret, []byte("should-not-be-read.txt\n"), 0644); err != nil {
		t.Fatal(err)
	}

	manifest := &storage.RunManifest{
		Target: "example.com",
		Outputs: map[string]string{
			"subfinder": "../../" + filepath.Base(secret),
		},
	}

	rep, err := GenerateReport(dir, manifest)
	if err == nil {
		t.Fatal("expected a refusal error for an escaping manifest path")
	}
	if len(rep.Assets) != 0 {
		t.Fatalf("traversal must not be parsed, got %d assets", len(rep.Assets))
	}
}

func TestMDInlineEscapesMarkdown(t *testing.T) {
	input := "a|b\n<script>alert(1)</script> *bold* `code` [x](y) \\path"
	out := mdInline(input)
	// No raw newline may survive (it would break table cells).
	if strings.Contains(out, "\n") {
		t.Errorf("mdInline left a newline in %q", out)
	}
	// Raw HTML angle brackets must be neutralized, not passed through.
	if strings.Contains(out, "<script") || strings.Contains(out, "</script") {
		t.Errorf("mdInline did not neutralize HTML: %q", out)
	}
	// Metacharacters must be backslash-escaped (or entity-encoded).
	for _, esc := range []string{"\\|", "\\*", "\\`", "\\[", "\\]", "&lt;"} {
		if !strings.Contains(out, esc) {
			t.Errorf("mdInline(%q) missing escape %q: %q", input, esc, out)
		}
	}
}
