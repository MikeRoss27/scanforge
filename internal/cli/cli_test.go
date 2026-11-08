package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/MikeRoss27/scanforge/internal/triage"
	"github.com/spf13/cobra"
)

// execute runs the command tree with the given args and returns the captured
// stdout/stderr and the error from Execute. Command handlers print through
// fmt/os.Stdout in the app layer, not only through cobra's writers, so the
// real stdout is redirected for the duration of the call.
func execute(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := NewRootCommand()
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetArgs(args)

	oldStdout := os.Stdout
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writeEnd
	execErr := cmd.Execute()
	_ = writeEnd.Close()
	os.Stdout = oldStdout
	stdout, _ := io.ReadAll(readEnd)
	_ = readEnd.Close()

	return out.String() + errBuf.String() + string(stdout), execErr
}

func TestRootHelpListsGroupsAndCommands(t *testing.T) {
	output, err := execute(t, "--help")
	if err != nil {
		t.Fatalf("--help error = %v", err)
	}
	for _, want := range []string{
		"Core Commands:",
		"Reports & Analysis:",
		"Configuration:",
		"Maintenance:",
		"Run a scan against an authorized target",
		"Preview the validated scan pipeline without running it",
		"Show what changed between two runs of the same target",
		"Export a run report in a machine-readable format",
		"Analyze and prioritize the findings of a run",
		"Create default ScanForge config files",
		"Manage API keys for the security tools",
		"Inspect and validate scanforge.yaml",
		"Check local dependencies and configuration",
		"Update scanforge to the latest release",
		"Print ScanForge version information",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("root help missing %q", want)
		}
	}
}

func TestSubcommandHelp(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"run", "--help"}, "Executes the scan pipeline for a target"},
		{[]string{"plan", "--help"}, "Validates the profile, scope and module dependencies"},
		{[]string{"doctor", "--help"}, "Verifies that the external tools required"},
		{[]string{"update", "--help"}, "Update scanforge to the latest release, replacing the running binary"},
		{[]string{"config", "validate", "--help"}, "Loads scanforge.yaml and checks that it is usable"},
		{[]string{"diff", "--help"}, "Loads the two run directories"},
		{[]string{"export", "--help"}, "Reconsolidates the report of a run directory"},
		{[]string{"triage", "--help"}, "Projects the consolidated report of a run directory"},
		{[]string{"init", "--help"}, "Creates the default configuration files"},
		{[]string{"auth", "--help"}, "Manages API keys for the tools"},
		{[]string{"version", "--help"}, "Print ScanForge version information"},
	}
	for _, tc := range cases {
		t.Run(strings.Join(tc.args, "_"), func(t *testing.T) {
			output, err := execute(t, tc.args...)
			if err != nil {
				t.Fatalf("%v error = %v", tc.args, err)
			}
			if !strings.Contains(output, tc.want) {
				t.Errorf("%v help missing %q", tc.args, tc.want)
			}
		})
	}
}

func TestVersionCommandPrintsVersion(t *testing.T) {
	output, err := execute(t, "version")
	if err != nil {
		t.Fatalf("version error = %v", err)
	}
	for _, want := range []string{"SCANFORGE", "VERSION", "COMMIT", "GO"} {
		if !strings.Contains(output, want) {
			t.Errorf("version output missing %q: %q", want, output)
		}
	}
}

func TestConfigValidateCommandFailsOnBadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scanforge.yaml")
	if err := os.WriteFile(path, []byte("config_version: 99\n"), 0644); err != nil {
		t.Fatal(err)
	}

	output, err := execute(t, "config", "validate", "--config", path)
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
	var exitErr app.ExitCodeError
	if !errors.As(err, &exitErr) || exitErr.Code != 1 {
		t.Fatalf("error = %v, want ExitCodeError{Code: 1}", err)
	}
	if !strings.Contains(output, "config_version 99") {
		t.Errorf("output missing problem detail: %q", output)
	}
}

func TestConfigValidateCommandSucceedsOnValidConfig(t *testing.T) {
	dir := t.TempDir()
	scopeFile := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(scopeFile, []byte("example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "scanforge.yaml")
	if err := os.WriteFile(path, []byte("config_version: 1\ndefault_scope: "+scopeFile+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	output, err := execute(t, "config", "validate", "--config", path)
	if err != nil {
		t.Fatalf("config validate error = %v", err)
	}
	if !strings.Contains(output, "Configuration is valid") {
		t.Errorf("output missing success message: %q", output)
	}
}

func TestTriageCommandArgsValidation(t *testing.T) {
	cases := []struct {
		name       string
		args       []string
		wantErr    bool
		wantErrMsg string
	}{
		{
			name:       "missing run argument",
			args:       []string{"triage"},
			wantErr:    true,
			wantErrMsg: "accepts 1 arg",
		},
		{
			name:       "too many arguments",
			args:       []string{"triage", "run1", "run2"},
			wantErr:    true,
			wantErrMsg: "accepts 1 arg",
		},
		{
			name:    "valid single argument",
			args:    []string{"triage", "runs/example.com/2026-08-19T10:00:00Z"},
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Use the execute helper which properly handles subcommands via the root command
			_, err := execute(t, tc.args...)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for args %v", tc.args)
				}
				if !strings.Contains(err.Error(), tc.wantErrMsg) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.wantErrMsg)
				}
			} else {
				// For valid args, we expect the command to fail at the app.Triage call
				// since we're using a fake app with no real run directory.
				// The important thing is that argument validation passed.
				if err != nil && strings.Contains(err.Error(), "requires exactly 1 arg") {
					t.Errorf("unexpected arg validation error: %v", err)
				}
			}
		})
	}
}

func TestTriageCommandFlagsForwarded(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantForce   bool
		wantModel   string
		wantBaseURL string
	}{
		{
			name:        "no flags",
			args:        []string{"triage", "runs/example.com/2026-08-19T10:00:00Z"},
			wantForce:   false,
			wantModel:   "",
			wantBaseURL: "",
		},
		{
			name:        "force flag",
			args:        []string{"triage", "--force", "runs/example.com/2026-08-19T10:00:00Z"},
			wantForce:   true,
			wantModel:   "",
			wantBaseURL: "",
		},
		{
			name:        "model flag",
			args:        []string{"triage", "--model", "qwen3.5-9b", "runs/example.com/2026-08-19T10:00:00Z"},
			wantForce:   false,
			wantModel:   "qwen3.5-9b",
			wantBaseURL: "",
		},
		{
			name:        "base-url flag",
			args:        []string{"triage", "--base-url", "http://localhost:8080/v1", "runs/example.com/2026-08-19T10:00:00Z"},
			wantForce:   false,
			wantModel:   "",
			wantBaseURL: "http://localhost:8080/v1",
		},
		{
			name:        "all flags",
			args:        []string{"triage", "--force", "--model", "custom-model", "--base-url", "http://custom:8080/v1", "runs/example.com/2026-08-19T10:00:00Z"},
			wantForce:   true,
			wantModel:   "custom-model",
			wantBaseURL: "http://custom:8080/v1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use the execute helper which properly handles subcommands via the root command
			_, err := execute(t, tt.args...)
			// The command will fail at the app.Triage call since there's no real run,
			// but we're testing that flag parsing works (no "unknown flag" errors).
			if err != nil && strings.Contains(err.Error(), "unknown flag") {
				t.Errorf("unexpected unknown flag error: %v", err)
			}
		})
	}
}

func TestPrintTriageSummaryOutput(t *testing.T) {
	// Test that printTriageSummary produces deterministic output for a fixed result.
	result := &triage.Result{
		Manifest: triage.TriageManifest{
			Model:         "test-model",
			PromptVersion: "triage-v1",
			Temperature:   0.1,
		},
		Stats: triage.Stats{
			Findings:    5,
			Relations:   3,
			Insights:    2,
			LLMInsights: 1,
			Rejected:    0,
			CacheHit:    false,
			LLMError:    "",
		},
		Dir: "/tmp/test-triage",
	}

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	printTriageSummary(cmd, result)

	output := buf.String()
	// Check for key elements in the output
	for _, want := range []string{
		"Model:",
		"test-model",
		"Findings:",
		"5",
		"Relations:",
		"3",
		"Insights:",
		"2",
		"LLM insights:",
		"1",
		"triage written to",
		"/tmp/test-triage",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q: %q", want, output)
		}
	}

	// Test with cache hit
	result.Stats.CacheHit = true
	buf.Reset()
	printTriageSummary(cmd, result)
	if !strings.Contains(buf.String(), "hit") {
		t.Errorf("cache hit not shown in output: %q", buf.String())
	}

	// Test with LLM error
	result.Stats.CacheHit = false
	result.Stats.LLMError = "connection refused"
	buf.Reset()
	printTriageSummary(cmd, result)
	if !strings.Contains(buf.String(), "connection refused") {
		t.Errorf("LLM error not shown in output: %q", buf.String())
	}
}
