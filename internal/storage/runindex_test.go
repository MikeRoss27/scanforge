package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteManifestIsAtomicAndLeavesNoTempFiles(t *testing.T) {
	run, err := NewRunStore(t.TempDir()).Create("example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{ModuleRunning, ModuleCompleted} {
		if err := run.UpdateModule(ModuleResult{Name: "dnsx", Status: status, InputHash: "abc"}); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := os.ReadDir(run.MetaDir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
	reopened, err := OpenRun(run.RootDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.Manifest.Modules) != 1 || reopened.Manifest.Modules[0].Status != ModuleCompleted {
		t.Fatalf("modules = %+v, want single upserted completed record", reopened.Manifest.Modules)
	}
}

func TestFindRunResolvesReferences(t *testing.T) {
	ws := t.TempDir()
	mk := func(target, id string) {
		dir := filepath.Join(ws, target, id, "00_meta")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		data := `{"id":"` + id + `","target":"` + target + `","started_at":"` + id + `","status":"completed","outputs":{}}`
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("a.com", "2026-01-01_00-00-00")
	mk("b.com", "2026-01-01_00-00-00")
	mk("a.com", "2026-02-01_00-00-00")

	tests := []struct {
		name    string
		ref     string
		wantDir string
		wantErr string
	}{
		{"unique id", "2026-02-01_00-00-00", filepath.Join(ws, "a.com", "2026-02-01_00-00-00"), ""},
		{"target/id", "b.com/2026-01-01_00-00-00", filepath.Join(ws, "b.com", "2026-01-01_00-00-00"), ""},
		{"ambiguous id", "2026-01-01_00-00-00", "", "ambiguous"},
		{"unknown", "nope", "", "not found"},
		{"empty", "", "", "required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run, err := FindRun(ws, tt.ref)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || run.RootDir != tt.wantDir {
				t.Fatalf("FindRun = %v, %v; want %s", run, err, tt.wantDir)
			}
		})
	}

	runs, err := ListRuns(ws)
	if err != nil || len(runs) != 3 || runs[0].ID != "2026-02-01_00-00-00" {
		t.Fatalf("ListRuns = %d runs (err %v), want 3 newest first", len(runs), err)
	}
}
