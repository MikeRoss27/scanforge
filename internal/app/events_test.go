package app

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

func TestFinalizeManifestStatus(t *testing.T) {
	completed := &modules.Result{Name: "httpx", Status: "completed"}
	notApplicable := &modules.Result{Name: "wpusers", Status: "skipped", Reason: "no WordPress detected"}
	dependencySkip := &modules.Result{Name: "nmap", Status: "skipped"}
	failed := &modules.Result{Name: "nuclei", Status: "failed"}

	tests := []struct {
		name    string
		results []*modules.Result
		runErr  error
		want    string
	}{
		{"all completed", []*modules.Result{completed}, nil, "completed"},
		{"not-applicable skip keeps the run complete", []*modules.Result{completed, notApplicable}, nil, "completed"},
		{"dependency skip is partial", []*modules.Result{completed, dependencySkip}, nil, "partial"},
		{"failure is partial", []*modules.Result{completed, notApplicable, failed}, errors.New("boom"), "partial"},
		{"nothing completed", []*modules.Result{failed}, errors.New("boom"), "failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			s := &runSession{scanRun: &storage.Run{
				RootDir:      dir,
				ManifestPath: filepath.Join(dir, "manifest.json"),
				Manifest:     storage.RunManifest{Outputs: map[string]string{}},
			}}
			if err := s.finalizeManifest(tt.results, tt.runErr); err != nil {
				t.Fatalf("finalizeManifest() error = %v", err)
			}
			if got := s.scanRun.Manifest.Status; got != tt.want {
				t.Errorf("status = %q, want %q", got, tt.want)
			}
		})
	}
}
