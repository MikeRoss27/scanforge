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

func TestOpenRunRoundTripsManifest(t *testing.T) {
	store := NewRunStore(t.TempDir())
	created, err := store.Create("example.com")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	created.Manifest.Status = "completed"
	created.Manifest.Outputs["cve_findings"] = "06_vulns/cve-findings.jsonl"
	if err := created.WriteManifest(); err != nil {
		t.Fatalf("WriteManifest() error = %v", err)
	}

	opened, err := OpenRun(created.RootDir)
	if err != nil {
		t.Fatalf("OpenRun() error = %v", err)
	}
	if opened.ID != created.ID || opened.Target != created.Target {
		t.Fatalf("OpenRun() = %+v, want target %q id %q", opened, created.Target, created.ID)
	}
	if opened.Manifest.Status != "completed" {
		t.Fatalf("manifest status = %q, want completed", opened.Manifest.Status)
	}
	if got := opened.Manifest.Outputs["cve_findings"]; got != "06_vulns/cve-findings.jsonl" {
		t.Fatalf("outputs not preserved: %v", opened.Manifest.Outputs)
	}
	if opened.MetaDir != filepath.Join(created.RootDir, "00_meta") {
		t.Fatalf("MetaDir = %q", opened.MetaDir)
	}
}

func TestOpenRunRejectsNonRunDirectory(t *testing.T) {
	if _, err := OpenRun(t.TempDir()); err == nil {
		t.Fatal("OpenRun() on a directory without manifest must fail")
	}
}
