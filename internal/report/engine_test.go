package report

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MikeRoss27/scanforge/internal/storage"
)

func TestGenerateReport(t *testing.T) {
	dir := t.TempDir()
	
	// Write dummy files
	os.WriteFile(filepath.Join(dir, "subfinder.txt"), []byte("example.com\n"), 0644)
	os.WriteFile(filepath.Join(dir, "naabu.txt"), []byte("example.com:80\n"), 0644)
	os.WriteFile(filepath.Join(dir, "httpx.jsonl"), []byte(`{"url":"http://example.com","host":"example.com","tech":["Nginx"]}`+"\n"), 0644)
	os.WriteFile(filepath.Join(dir, "nuclei.jsonl"), []byte(`{"template-id":"test-cve","matched-at":"example.com","host":"example.com","info":{"name":"Test","severity":"high"}}`+"\n"), 0644)

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
