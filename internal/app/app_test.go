package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRunDryRun(t *testing.T) {
	dir := t.TempDir()

	scopePath := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(scopePath, []byte("example.com\n"), 0644); err != nil {
		t.Fatalf("failed to write scope file: %v", err)
	}

	workspace := filepath.Join(dir, "runs")
	configPath := filepath.Join(dir, "scanforge.yaml")
	configContent := "workspace: " + workspace + "\ndefault_scope: " + scopePath + "\n"
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	app := New(configPath)

	err := app.Run(context.Background(), RunOptions{
		Target:  "example.com",
		Profile: "passive",
		Scope:   scopePath,
		DryRun:  true,
		Verbose: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entries, err := os.ReadDir(workspace)
	if err != nil {
		t.Fatalf("expected workspace to exist: %v", err)
	}

	if len(entries) == 0 {
		t.Fatal("expected at least one run directory")
	}
}

func TestRunRejectsOutOfScopeTarget(t *testing.T) {
	dir := t.TempDir()

	scopePath := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(scopePath, []byte("allowed.com\n"), 0644); err != nil {
		t.Fatalf("failed to write scope file: %v", err)
	}

	app := New("")

	err := app.Run(context.Background(), RunOptions{
		Target: "denied.com",
		Scope:  scopePath,
		DryRun: true,
	})
	if err == nil {
		t.Fatal("expected out-of-scope error")
	}
}
