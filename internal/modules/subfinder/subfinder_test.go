package subfinder

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
	scanScope "github.com/MikeRoss27/scanforge/internal/scope"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

type outputExecutor struct {
	command runner.Command
	output  string
}

func (e *outputExecutor) Run(_ context.Context, command runner.Command) (*runner.CommandResult, error) {
	e.command = command
	if err := os.WriteFile(command.StdoutFile, []byte(e.output), 0644); err != nil {
		return nil, err
	}
	return &runner.CommandResult{Command: command}, nil
}

func TestRunNormalizesURLAndKeepsRootTarget(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"00_meta", "01_subdomains"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	run := &storage.Run{
		RootDir:     root,
		MetaDir:     filepath.Join(root, "00_meta"),
		CommandsLog: filepath.Join(root, "00_meta", "commands.log"),
	}
	allowed, err := scanScope.FromTarget("https://Example.COM:443/path", scanScope.ModeExact, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("https://Example.COM:443/path", "passive", false, run, allowed)
	executor := &outputExecutor{output: "api.example.com\n"}

	if _, err := New("subfinder-test").Run(context.Background(), runCtx, executor); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got, want := executor.command.Args, []string{"-d", "example.com", "-silent"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("command args = %v, want %v", got, want)
	}
	data, err := os.ReadFile(filepath.Join(root, "01_subdomains", "subfinder.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "example.com\n"; got != want {
		t.Fatalf("filtered output = %q, want %q", got, want)
	}
	rejections, err := os.ReadFile(filepath.Join(root, "00_meta", "scope-rejections.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rejections), "api.example.com") {
		t.Fatalf("rejection log = %q, missing rejected subdomain", rejections)
	}
}

func TestEnsureTargetInOutputDoesNotDuplicateTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subfinder.txt")
	if err := os.WriteFile(path, []byte("EXAMPLE.COM\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := ensureTargetInOutput(path, "example.com"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(strings.ToLower(string(data)), "example.com"); got != 1 {
		t.Fatalf("target count = %d, want 1; output = %q", got, data)
	}
}
