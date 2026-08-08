package orchestrator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

func TestModuleSummary(t *testing.T) {
	run := &storage.Run{RootDir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(run.RootDir, "subs.txt"), []byte("a.com\nb.com\n\nc.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "test", false, run)
	if err := runCtx.AddArtifact("subdomains", modules.Artifact{Name: "subdomains", Type: "text", Path: "subs.txt"}); err != nil {
		t.Fatal(err)
	}

	mod := &mockModule{name: "subfinder", produces: []string{"subdomains"}}
	got := moduleSummary(runCtx, mod, &modules.Result{Name: "subfinder", Status: "completed"})
	if got != "3 subdomains" {
		t.Errorf("expected %q, got %q", "3 subdomains", got)
	}
}

func TestModuleSummarySkipsEmptyOutputAndDryRun(t *testing.T) {
	run := &storage.Run{RootDir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(run.RootDir, "subs.txt"), []byte("\n\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "test", false, run)
	if err := runCtx.AddArtifact("subdomains", modules.Artifact{Name: "subdomains", Type: "text", Path: "subs.txt"}); err != nil {
		t.Fatal(err)
	}
	mod := &mockModule{name: "subfinder", produces: []string{"subdomains"}}

	if got := moduleSummary(runCtx, mod, &modules.Result{Name: "subfinder", Status: "completed"}); got != "" {
		t.Errorf("expected empty summary for empty file, got %q", got)
	}
	if got := moduleSummary(runCtx, mod, &modules.Result{Name: "subfinder", Status: "failed"}); got != "" {
		t.Errorf("expected empty summary for failed module, got %q", got)
	}

	dry := modules.NewRunContext("example.com", "test", true, run)
	if got := moduleSummary(dry, mod, &modules.Result{Name: "subfinder", Status: "completed"}); got != "" {
		t.Errorf("expected empty summary for dry run, got %q", got)
	}
}

func TestModuleSummaryFallsBackToRawArtifact(t *testing.T) {
	run := &storage.Run{RootDir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(run.RootDir, "raw.jsonl"), []byte("{\"a\":1}\n{\"b\":2}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "test", false, run)
	if err := runCtx.AddArtifact("nuclei_raw", modules.Artifact{Name: "nuclei_raw", Type: "jsonl", Path: "raw.jsonl"}); err != nil {
		t.Fatal(err)
	}

	mod := &mockModule{name: "nuclei", produces: []string{"nuclei_raw"}}
	got := moduleSummary(runCtx, mod, &modules.Result{Name: "nuclei", Status: "completed"})
	if got != "2 findings" {
		t.Errorf("expected %q, got %q", "2 findings", got)
	}
}
