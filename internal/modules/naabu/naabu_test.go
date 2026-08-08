package naabu

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

type recordingExecutor struct {
	commands []runner.Command
}

func (e *recordingExecutor) Run(_ context.Context, command runner.Command) (*runner.CommandResult, error) {
	e.commands = append(e.commands, command)
	return &runner.CommandResult{Command: command, ExitCode: 0}, nil
}

func testRun(t *testing.T, root string) *storage.Run {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "00_meta"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "01_subdomains"), 0755); err != nil {
		t.Fatal(err)
	}
	return &storage.Run{RootDir: root, CommandsLog: filepath.Join(root, "00_meta", "commands.log")}
}

func TestRequiresResolvedHosts(t *testing.T) {
	if got, want := New("").Requires(), []string{"resolved_hosts"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Requires() = %v, want %v", got, want)
	}
}

func TestRunBuildsNaabuCommandAndPublishesPorts(t *testing.T) {
	run := testRun(t, t.TempDir())
	inputPath := run.Path("01_subdomains", "resolved.txt")
	if err := os.WriteFile(inputPath, []byte("example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "ports", false, run)
	if err := runCtx.AddArtifact("resolved_hosts", modules.Artifact{Name: "resolved_hosts", Type: "text", Path: "01_subdomains/resolved.txt"}); err != nil {
		t.Fatal(err)
	}
	executor := &recordingExecutor{}

	result, err := New("naabu-test").Run(context.Background(), runCtx, executor)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("status = %q, want completed", result.Status)
	}
	cmd := executor.commands[0]
	if cmd.Name != "naabu-test" {
		t.Fatalf("command name = %q", cmd.Name)
	}
	args := strings.Join(cmd.Args, " ")
	for _, want := range []string{"-l", inputPath, "-silent"} {
		if !strings.Contains(args, want) {
			t.Errorf("args %q missing %q", args, want)
		}
	}
	if cmd.StdoutFile != run.Path("03_ports", "naabu.txt") {
		t.Errorf("stdout file = %q", cmd.StdoutFile)
	}
	if _, ok := runCtx.GetArtifact("open_ports"); !ok {
		t.Fatal("open_ports artifact was not published")
	}
}

func TestRunFailsWithoutResolvedHosts(t *testing.T) {
	run := testRun(t, t.TempDir())
	runCtx := modules.NewRunContext("example.com", "ports", false, run)
	if _, err := New("naabu").Run(context.Background(), runCtx, &recordingExecutor{}); err == nil {
		t.Fatal("expected error for missing resolved_hosts artifact")
	}
}
