package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPlanBuildsValidatedReconWaves(t *testing.T) {
	dir := t.TempDir()
	scopePath := filepath.Join(dir, "scope.txt")
	configPath := filepath.Join(dir, "scanforge.yaml")
	if err := os.WriteFile(scopePath, []byte("example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("default_scope: "+scopePath+"\ndefault_profile: recon\n"), 0644); err != nil {
		t.Fatal(err)
	}
	results, err := New(configPath).Plan(PlanOptions{Target: "example.com"})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("plan count = %d, want 1", len(results))
	}
	result := results[0]
	if len(result.Steps) != 5 {
		t.Fatalf("step count = %d, want 5", len(result.Steps))
	}
	waves := make(map[string]int)
	for _, step := range result.Steps {
		waves[step.Name] = step.Wave
	}
	if waves["subfinder"] != 1 || waves["gau"] != 1 || waves["dnsx"] != 2 || waves["httpx"] != 3 || waves["tlsx"] != 4 {
		t.Fatalf("unexpected plan waves: %v", waves)
	}
}
