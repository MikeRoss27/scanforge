package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/storage"
)

func firstRunDir(t *testing.T, root string) string {
	t.Helper()
	runs, err := os.ReadDir(filepath.Join(root, "runs", "example.com"))
	if err != nil || len(runs) == 0 {
		t.Fatalf("no run directory: %v", err)
	}
	return filepath.Join(root, "runs", "example.com", runs[0].Name())
}

func TestResumeDryRunRunKeepsStoredScopeAndRecordsCheckpoints(t *testing.T) {
	root := t.TempDir()
	app := New(writeTestConfig(t, root))
	if err := app.Run(context.Background(), RunOptions{Target: "example.com", Profile: "passive", DryRun: true, ConfirmScope: true}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	runDir := firstRunDir(t, root)
	run, err := storage.OpenRun(runDir)
	if err != nil {
		t.Fatal(err)
	}
	if run.Manifest.ScopeSHA256 == "" || run.Manifest.Params == nil || !run.Manifest.DryRun {
		t.Fatalf("manifest lacks resume metadata: %+v", run.Manifest)
	}
	for _, rec := range run.Manifest.Modules {
		if rec.Status != storage.ModuleCompleted || rec.InputHash == "" {
			t.Errorf("module %s checkpoint = %+v", rec.Name, rec)
		}
	}

	// Simulate an interruption: the manifest says the run was still going.
	run.Manifest.Status = "running"
	run.Manifest.Modules[len(run.Manifest.Modules)-1].Status = storage.ModuleRunning
	if err := run.WriteManifest(); err != nil {
		t.Fatal(err)
	}
	scopeBefore, _ := os.ReadFile(run.Path("00_meta", "effective-scope.txt"))

	if err := app.Resume(context.Background(), ResumeOptions{Run: run.ID}); err != nil {
		t.Fatalf("Resume() error = %v", err)
	}
	resumed, err := storage.OpenRun(runDir)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Manifest.Status != "completed" || resumed.Manifest.ResumeCount != 1 {
		t.Errorf("status=%q resume_count=%d", resumed.Manifest.Status, resumed.Manifest.ResumeCount)
	}
	scopeAfter, _ := os.ReadFile(run.Path("00_meta", "effective-scope.txt"))
	if string(scopeBefore) != string(scopeAfter) {
		t.Errorf("effective scope changed on resume")
	}
}

func TestResumeRefusesTamperedOrLegacyScope(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, run *storage.Run)
		want   string
	}{
		{"scope widened", func(t *testing.T, run *storage.Run) {
			f, err := os.OpenFile(run.Path("00_meta", "effective-scope.txt"), os.O_APPEND|os.O_WRONLY, 0o644)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			if _, err := f.WriteString("*.evil.org\n"); err != nil {
				t.Fatal(err)
			}
		}, "modified"},
		{"legacy run without digest", func(t *testing.T, run *storage.Run) {
			run.Manifest.ScopeSHA256 = ""
			if err := run.WriteManifest(); err != nil {
				t.Fatal(err)
			}
		}, "predates checkpoints"},
		{"scope file removed", func(t *testing.T, run *storage.Run) {
			if err := os.Remove(run.Path("00_meta", "effective-scope.txt")); err != nil {
				t.Fatal(err)
			}
		}, "effective scope"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			app := New(writeTestConfig(t, root))
			if err := app.Run(context.Background(), RunOptions{Target: "example.com", Profile: "passive", DryRun: true, ConfirmScope: true}); err != nil {
				t.Fatal(err)
			}
			run, err := storage.OpenRun(firstRunDir(t, root))
			if err != nil {
				t.Fatal(err)
			}
			tt.mutate(t, run)
			err = app.Resume(context.Background(), ResumeOptions{Run: run.ID})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Resume() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestStatusAndListRuns(t *testing.T) {
	root := t.TempDir()
	app := New(writeTestConfig(t, root))
	if err := app.Run(context.Background(), RunOptions{Target: "example.com", Profile: "passive", DryRun: true, ConfirmScope: true}); err != nil {
		t.Fatal(err)
	}
	runs, err := app.ListRuns("")
	if err != nil || len(runs) != 1 {
		t.Fatalf("ListRuns() = %d runs, err %v", len(runs), err)
	}
	if other, _ := app.ListRuns("other.com"); len(other) != 0 {
		t.Errorf("target filter returned %d runs", len(other))
	}
	if table := FormatRunList(runs); !strings.Contains(table, runs[0].ID) || !strings.Contains(table, "example.com") {
		t.Errorf("run list = %q", table)
	}
	_, text, err := app.RunStatus(runs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "completed") || !strings.Contains(text, "Target:    example.com") {
		t.Errorf("status = %q", text)
	}
}
