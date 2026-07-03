package initcmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunCreatesFiles(t *testing.T) {
	t.Chdir(t.TempDir())

	result, err := Run(Options{Force: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Created) < 3 {
		t.Fatalf("expected at least 3 created files, got %v", result.Created)
	}

	for _, name := range []string{"scanforge.yaml", "scope.txt", filepath.Join("runs", ".gitkeep")} {
		if _, err := os.Stat(name); err != nil {
			t.Fatalf("expected %q to exist: %v", name, err)
		}
	}
}

func TestRunConflictWithoutForce(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	if _, err := Run(Options{Force: false}); err != nil {
		t.Fatalf("first init failed: %v", err)
	}

	result, err := Run(Options{Force: false})
	if err == nil {
		t.Fatal("expected conflict error")
	}

	if len(result.Skipped) == 0 {
		t.Fatal("expected skipped files")
	}
}

func TestRunForceOverwrite(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	if _, err := Run(Options{Force: false}); err != nil {
		t.Fatalf("first init failed: %v", err)
	}

	if err := os.WriteFile("scope.txt", []byte("custom"), 0644); err != nil {
		t.Fatalf("failed to seed scope file: %v", err)
	}

	if _, err := Run(Options{Force: true}); err != nil {
		t.Fatalf("force init failed: %v", err)
	}

	data, err := os.ReadFile("scope.txt")
	if err != nil {
		t.Fatalf("failed to read scope file: %v", err)
	}

	if string(data) == "custom" {
		t.Fatal("expected scope file to be overwritten")
	}
}
