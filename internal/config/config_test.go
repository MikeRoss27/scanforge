package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

	// The web profile chains recon into detection: subdomain discovery,
	// probing, fingerprinting, crawling, JS analysis, the consolidated attack
	// surface and the vulnerability scanners.
	required := []string{
		"subfinder", "dnsx", "httpx", "whatweb", "wafw00f", "katana",
		"jssecrets", "attacksurface", "techcve", "httpcheck", "nuclei",
	}
	for _, name := range required {
		found := false
		for _, m := range modules {
			if m == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("web profile missing module %q (got %v)", name, modules)
		}
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

func TestLoadModuleTimeouts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scanforge.yaml")

	content := `config_version: 1
module_timeouts:
  nuclei: 45m
  katana: 1h30m
  ffuf: 0s
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := cfg.ModuleTimeouts["nuclei"]; got != 45*time.Minute {
		t.Fatalf("nuclei timeout = %v, want 45m", got)
	}
	if got := cfg.ModuleTimeouts["katana"]; got != 90*time.Minute {
		t.Fatalf("katana timeout = %v, want 1h30m", got)
	}
	if got := cfg.ModuleTimeouts["ffuf"]; got != 0 {
		t.Fatalf("ffuf timeout = %v, want 0 (module default)", got)
	}
}

func TestLoadInvalidModuleTimeout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scanforge.yaml")

	content := `config_version: 1
module_timeouts:
  nuclei: not-a-duration
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("expected a parse error for an invalid duration")
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

func TestLoadAI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scanforge.yaml")

	content := `config_version: 1
ai:
  base_url: http://127.0.0.1:8080/v1
  model: qwen3.5-9b
  api_key: secret
  timeout: 2m
  temperature: 0.05
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AI.BaseURL != "http://127.0.0.1:8080/v1" {
		t.Errorf("base_url = %q", cfg.AI.BaseURL)
	}
	if cfg.AI.Model != "qwen3.5-9b" {
		t.Errorf("model = %q", cfg.AI.Model)
	}
	if cfg.AI.APIKey != "secret" {
		t.Errorf("api_key = %q", cfg.AI.APIKey)
	}
	if cfg.AI.Timeout != 2*time.Minute {
		t.Errorf("timeout = %v, want 2m", cfg.AI.Timeout)
	}
	if cfg.AI.Temperature != 0.05 {
		t.Errorf("temperature = %v, want 0.05", cfg.AI.Temperature)
	}
}

func TestLoadAIMergesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scanforge.yaml")

	content := `config_version: 1
ai:
  base_url: http://127.0.0.1:8080/v1
  model: qwen3.5-9b
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AI.Timeout != DefaultAITimeout {
		t.Errorf("timeout = %v, want default %v", cfg.AI.Timeout, DefaultAITimeout)
	}
	if cfg.AI.Temperature != DefaultAITemperature {
		t.Errorf("temperature = %v, want default %v", cfg.AI.Temperature, DefaultAITemperature)
	}
}

func TestYAMLTemplateIncludesAI(t *testing.T) {
	cfg := Default()
	template := cfg.YAMLTemplate()
	for _, want := range []string{"ai:", "base_url:", "temperature:"} {
		if !strings.Contains(template, want) {
			t.Errorf("template missing %q", want)
		}
	}
}
