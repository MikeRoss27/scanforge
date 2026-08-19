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
