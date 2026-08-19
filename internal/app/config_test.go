package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scanforge.yaml")
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateConfigValid(t *testing.T) {
	scopeFile := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(scopeFile, []byte("example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	app := New(writeConfig(t, "config_version: 1\ndefault_scope: "+scopeFile+"\n"))
	result, err := app.ValidateConfig(t.Context())
	if err != nil {
		t.Fatalf("ValidateConfig() error = %v", err)
	}
	if len(result.Problems) != 0 {
		t.Fatalf("unexpected problems: %v", result.Problems)
	}
	if len(result.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", result.Warnings)
	}
}

func TestValidateConfigUnsupportedVersion(t *testing.T) {
	app := New(writeConfig(t, "config_version: 99\n"))
	result, err := app.ValidateConfig(t.Context())
	if err != nil {
		t.Fatalf("ValidateConfig() error = %v", err)
	}
	if len(result.Problems) != 1 || !strings.Contains(result.Problems[0], "config_version 99") {
		t.Fatalf("problems = %v, want config_version complaint", result.Problems)
	}
}

func TestValidateConfigUnknownDefaultProfile(t *testing.T) {
	app := New(writeConfig(t, "config_version: 1\ndefault_profile: nope\n"))
	result, err := app.ValidateConfig(t.Context())
	if err != nil {
		t.Fatalf("ValidateConfig() error = %v", err)
	}
	if len(result.Problems) != 1 || !strings.Contains(result.Problems[0], `default_profile "nope"`) {
		t.Fatalf("problems = %v, want default_profile complaint", result.Problems)
	}
}

func TestValidateConfigProfileReferencesUnknownModule(t *testing.T) {
	app := New(writeConfig(t, `config_version: 1
profiles:
  custom:
    - subfinder
    - not-a-module
`))
	result, err := app.ValidateConfig(t.Context())
	if err != nil {
		t.Fatalf("ValidateConfig() error = %v", err)
	}
	if len(result.Problems) != 1 || !strings.Contains(result.Problems[0], `profile "custom" references unknown module "not-a-module"`) {
		t.Fatalf("problems = %v, want unknown module complaint", result.Problems)
	}
}

func TestValidateConfigModuleTimeoutUnknownModule(t *testing.T) {
	app := New(writeConfig(t, `config_version: 1
module_timeouts:
  nuclei: 45m
  not-a-module: 10m
`))
	result, err := app.ValidateConfig(t.Context())
	if err != nil {
		t.Fatalf("ValidateConfig() error = %v", err)
	}
	if len(result.Problems) != 1 || !strings.Contains(result.Problems[0], `module_timeouts references unknown module "not-a-module"`) {
		t.Fatalf("problems = %v, want unknown module complaint", result.Problems)
	}
}

func TestValidateConfigModuleTimeoutKnownModule(t *testing.T) {
	app := New(writeConfig(t, `config_version: 1
module_timeouts:
  nuclei: 45m
`))
	result, err := app.ValidateConfig(t.Context())
	if err != nil {
		t.Fatalf("ValidateConfig() error = %v", err)
	}
	if len(result.Problems) != 0 {
		t.Fatalf("unexpected problems: %v", result.Problems)
	}
}

func TestValidateConfigCustomToolPathMissing(t *testing.T) {
	app := New(writeConfig(t, `config_version: 1
tools:
  nuclei: /nonexistent/nuclei
`))
	result, err := app.ValidateConfig(t.Context())
	if err != nil {
		t.Fatalf("ValidateConfig() error = %v", err)
	}
	if len(result.Problems) != 1 || !strings.Contains(result.Problems[0], `tool "nuclei" path "/nonexistent/nuclei" does not exist`) {
		t.Fatalf("problems = %v, want missing tool path complaint", result.Problems)
	}
}

func TestValidateConfigCustomToolPathExists(t *testing.T) {
	tool := filepath.Join(t.TempDir(), "nuclei")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}

	app := New(writeConfig(t, "config_version: 1\ntools:\n  nuclei: "+tool+"\n"))
	result, err := app.ValidateConfig(t.Context())
	if err != nil {
		t.Fatalf("ValidateConfig() error = %v", err)
	}
	for _, problem := range result.Problems {
		if strings.Contains(problem, "nuclei") {
			t.Fatalf("unexpected tool problem: %v", result.Problems)
		}
	}
}

func TestValidateConfigMissingScopeFileIsWarning(t *testing.T) {
	app := New(writeConfig(t, "config_version: 1\ndefault_scope: /nonexistent/scope.txt\n"))
	result, err := app.ValidateConfig(t.Context())
	if err != nil {
		t.Fatalf("ValidateConfig() error = %v", err)
	}
	if len(result.Problems) != 0 {
		t.Fatalf("unexpected problems: %v", result.Problems)
	}
	if len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "default_scope") {
		t.Fatalf("warnings = %v, want missing scope warning", result.Warnings)
	}
}

func TestValidateConfigBrokenScopeFileIsProblem(t *testing.T) {
	scopeFile := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(scopeFile, []byte("not a valid host!!!\n"), 0644); err != nil {
		t.Fatal(err)
	}

	app := New(writeConfig(t, "config_version: 1\ndefault_scope: "+scopeFile+"\n"))
	result, err := app.ValidateConfig(t.Context())
	if err != nil {
		t.Fatalf("ValidateConfig() error = %v", err)
	}
	if len(result.Problems) != 1 || !strings.Contains(result.Problems[0], "default_scope") {
		t.Fatalf("problems = %v, want broken scope complaint", result.Problems)
	}
}

func TestValidateConfigMissingFileReturnsDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	app := New(path)
	result, err := app.ValidateConfig(t.Context())
	if err != nil {
		t.Fatalf("ValidateConfig() error = %v", err)
	}
	// A missing config file is a valid (default) configuration: scope.txt
	// absent from the working directory is the only expected warning.
	if len(result.Problems) != 0 {
		t.Fatalf("unexpected problems: %v", result.Problems)
	}
	if result.Path != path {
		t.Fatalf("path = %q, want %q", result.Path, path)
	}
}

func TestValidateConfigAI(t *testing.T) {
	tests := []struct {
		name             string
		config           string
		wantProblems     []string
		wantNoAIProblems bool
	}{
		{
			name: "valid ai config",
			config: `config_version: 1
ai:
  base_url: http://127.0.0.1:8080/v1
  model: qwen3.5-9b
  temperature: 0.1
`,
			wantNoAIProblems: true,
		},
		{
			name: "missing base_url",
			config: `config_version: 1
ai:
  model: qwen3.5-9b
`,
			wantProblems: []string{"ai.base_url"},
		},
		{
			name: "missing model",
			config: `config_version: 1
ai:
  base_url: http://127.0.0.1:8080/v1
`,
			wantProblems: []string{"ai.model"},
		},
		{
			name: "bad base_url",
			config: `config_version: 1
ai:
  base_url: not a url
  model: qwen3.5-9b
`,
			wantProblems: []string{"ai.base_url"},
		},
		{
			name: "temperature out of range",
			config: `config_version: 1
ai:
  base_url: http://127.0.0.1:8080/v1
  model: qwen3.5-9b
  temperature: 3.5
`,
			wantProblems: []string{"ai.temperature"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := New(writeConfig(t, tt.config))
			result, err := app.ValidateConfig(t.Context())
			if err != nil {
				t.Fatalf("ValidateConfig() error = %v", err)
			}
			if tt.wantNoAIProblems {
				for _, problem := range result.Problems {
					if strings.Contains(problem, "ai.") {
						t.Fatalf("unexpected ai problem: %v", result.Problems)
					}
				}
				return
			}
			for _, want := range tt.wantProblems {
				if !containsProblem(result.Problems, want) {
					t.Fatalf("problems = %v, want %q complaint", result.Problems, want)
				}
			}
		})
	}
}

func containsProblem(problems []string, needle string) bool {
	for _, problem := range problems {
		if strings.Contains(problem, needle) {
			return true
		}
	}
	return false
}
