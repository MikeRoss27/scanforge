package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault(t *testing.T) {
	cfg := Default()

	if cfg.Workspace != DefaultWorkspace {
		t.Fatalf("expected workspace %q, got %q", DefaultWorkspace, cfg.Workspace)
	}

	if cfg.DefaultProfile != DefaultProfile {
		t.Fatalf("expected default profile %q, got %q", DefaultProfile, cfg.DefaultProfile)
	}

	modules, err := cfg.ProfileModules("web")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(modules) != 3 {
		t.Fatalf("expected 3 modules for web profile, got %d", len(modules))
	}
}

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.DefaultScope != DefaultScope {
		t.Fatalf("expected default scope %q, got %q", DefaultScope, cfg.DefaultScope)
	}
}

func TestLoadPartialMerge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scanforge.yaml")

	content := `workspace: custom-runs
default_profile: web
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Workspace != "custom-runs" {
		t.Fatalf("expected workspace custom-runs, got %q", cfg.Workspace)
	}

	if cfg.DefaultScope != DefaultScope {
		t.Fatalf("expected merged default scope %q, got %q", DefaultScope, cfg.DefaultScope)
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scanforge.yaml")

	if err := os.WriteFile(path, []byte(":\n  bad"), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestResolvePath(t *testing.T) {
	t.Setenv("SCANFORGE_CONFIG", "env.yaml")

	if got := ResolvePath("explicit.yaml"); got != "explicit.yaml" {
		t.Fatalf("expected explicit path, got %q", got)
	}

	if got := ResolvePath(""); got != "env.yaml" {
		t.Fatalf("expected env path, got %q", got)
	}
}

func TestToolPath(t *testing.T) {
	cfg := Default()
	cfg.Tools.Subfinder = "/usr/local/bin/subfinder"

	if got := cfg.ToolPath("subfinder"); got != "/usr/local/bin/subfinder" {
		t.Fatalf("unexpected tool path: %q", got)
	}
}
