package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MikeRoss27/scanforge/internal/storage"
)

// TestExportSurvivesOneCorruptArtifact: report.GenerateReport downgrades a
// single corrupt/truncated artifact to a warning and still returns every
// other module's data (see report.TestGenerateReportBestEffort). Export must
// honor that contract instead of treating the warning as fatal and discarding
// the whole report over one bad file.
func TestExportSurvivesOneCorruptArtifact(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"00_meta", "02_http", "05_content"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// A valid httpx artifact that should still make it into the report.
	if err := os.WriteFile(filepath.Join(dir, "02_http", "httpx.jsonl"),
		[]byte(`{"url":"http://example.com","host":"example.com","tech":["Nginx"]}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A truncated ffuf artifact: ParseFfuf unmarshals the whole file as one
	// JSON document, so a partial write makes it return a hard error.
	if err := os.WriteFile(filepath.Join(dir, "05_content", "ffuf.json"),
		[]byte(`{"results":[{"url":"http://example.com/admin"`), 0o644); err != nil {
		t.Fatal(err)
	}

	manifest := storage.RunManifest{
		ID:          "test-run",
		Target:      "example.com",
		Profile:     "web",
		StartedAt:   time.Now().Format(time.RFC3339),
		CompletedAt: time.Now().Format(time.RFC3339),
		Status:      "completed",
		Outputs: map[string]string{
			"httpx_raw":        "02_http/httpx.jsonl",
			"discovered_paths": "05_content/ffuf.json",
		},
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "00_meta", "manifest.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	a := &App{}
	out, err := a.Export(context.Background(), ExportOptions{Run: dir, Format: ExportSARIF})
	if err != nil {
		t.Fatalf("Export returned an error despite one corrupt artifact (should degrade gracefully): %v", err)
	}
	if _, statErr := os.Stat(out); statErr != nil {
		t.Fatalf("expected SARIF output at %s: %v", out, statErr)
	}
}
