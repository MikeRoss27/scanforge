package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromFileRoundTrips(t *testing.T) {
	rep := NewReport("example.com", "web")
	rep.Status = "completed"
	rep.Assets["example.com"] = &Asset{
		Name:         "example.com",
		Technologies: []string{"nginx"},
		Vulnerabilities: []*Vulnerability{
			{Title: "Reflected XSS", Severity: "medium", Tags: []string{"xss"}},
		},
	}

	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	got, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}
	if got.Target != "example.com" || got.Status != "completed" {
		t.Fatalf("LoadFromFile() = %+v", got)
	}
	asset := got.Assets["example.com"]
	if asset == nil || len(asset.Vulnerabilities) != 1 || asset.Vulnerabilities[0].Title != "Reflected XSS" {
		t.Fatalf("asset not round-tripped correctly: %+v", asset)
	}
}

func TestLoadFromFileMissing(t *testing.T) {
	if _, err := LoadFromFile(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("expected an error for a missing report file")
	}
}

func TestLoadFromFileMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFromFile(path); err == nil {
		t.Fatal("expected an error for a malformed report file")
	}
}
