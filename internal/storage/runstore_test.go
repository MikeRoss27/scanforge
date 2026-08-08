package storage

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSafeTargetNameRejectsTraversal(t *testing.T) {
	for _, target := range []string{"..", ".", "../..", "a/../b", "https://../"} {
		clean := safeTargetName(target)
		if clean == "" || strings.Contains(clean, "/") || strings.Contains(clean, "..") {
			t.Fatalf("safeTargetName(%q) = %q, must be a safe label", target, clean)
		}
		// Creating the run must never escape the workspace.
		store := NewRunStore(t.TempDir())
		run, err := store.Create(target)
		if err != nil {
			t.Fatalf("Create(%q) error = %v", target, err)
		}
		rel, err := filepath.Rel(store.Workspace, run.RootDir)
		if err != nil || strings.HasPrefix(rel, "..") {
			t.Fatalf("Create(%q) wrote outside workspace: %q", target, run.RootDir)
		}
	}
}

func TestCreateUniqueRunDirectories(t *testing.T) {
	store := NewRunStore(t.TempDir())

	first, err := store.Create("example.com")
	if err != nil {
		t.Fatalf("first Create() error = %v", err)
	}
	second, err := store.Create("example.com")
	if err != nil {
		t.Fatalf("second Create() error = %v", err)
	}

	if first.ID == second.ID {
		t.Fatalf("runs share the same ID %q", first.ID)
	}
	if first.RootDir == second.RootDir {
		t.Fatalf("runs share the same directory %q", first.RootDir)
	}
}

func TestCreateRunDirectoryExists(t *testing.T) {
	store := NewRunStore(t.TempDir())

	run, err := store.Create("example.com")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	_, err = store.Create("example.com")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if run.ID == "" {
		t.Fatal("expected a non-empty run ID")
	}
}
