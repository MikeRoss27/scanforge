package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunDryRunCompletesEndToEnd(t *testing.T) {
	root := t.TempDir()
	app := New(writeTestConfig(t, root))

	err := app.Run(context.Background(), RunOptions{
		Target:       "example.com",
		Profile:      "passive",
		DryRun:       true,
		ConfirmScope: true,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	runs, err := os.ReadDir(filepath.Join(root, "runs", "example.com"))
	if err != nil {
		t.Fatalf("expected runs/example.com directory: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("expected one run directory, got %d", len(runs))
	}
	runDir := filepath.Join(root, "runs", "example.com", runs[0].Name())

	for _, file := range []string{
		"00_meta/manifest.json",
		"00_meta/effective-scope.txt",
		"00_meta/commands.log",
		"report.json",
		"report.md",
	} {
		if _, err := os.Stat(filepath.Join(runDir, file)); err != nil {
			t.Errorf("missing %s: %v", file, err)
		}
	}

	manifestData, err := os.ReadFile(filepath.Join(runDir, "00_meta", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := string(manifestData)
	if !strings.Contains(manifest, `"status": "completed"`) {
		t.Errorf("manifest status not completed: %s", manifest)
	}
	if !strings.Contains(manifest, `"profile": "passive"`) {
		t.Errorf("manifest profile not set: %s", manifest)
	}
}

func TestRunRejectsMissingTarget(t *testing.T) {
	app := New(writeTestConfig(t, t.TempDir()))
	if err := app.Run(context.Background(), RunOptions{Profile: "passive", DryRun: true}); err == nil {
		t.Fatal("expected error for missing target")
	}
}

func TestRunRejectsUnknownProfile(t *testing.T) {
	app := New(writeTestConfig(t, t.TempDir()))
	err := app.Run(context.Background(), RunOptions{
		Target:       "example.com",
		Profile:      "does-not-exist",
		DryRun:       true,
		ConfirmScope: true,
	})
	if err == nil || !strings.Contains(err.Error(), "profile") {
		t.Fatalf("expected profile error, got %v", err)
	}
}
