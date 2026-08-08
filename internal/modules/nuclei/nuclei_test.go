package nuclei

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
	if err := os.MkdirAll(filepath.Join(root, "02_http"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "04_surface"), 0755); err != nil {
		t.Fatal(err)
	}
	return &storage.Run{RootDir: root, CommandsLog: filepath.Join(root, "00_meta", "commands.log")}
}

func TestRequiresAttackSurface(t *testing.T) {
	if got, want := New("").Requires(), []string{"attack_surface_urls"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Requires() = %v, want %v", got, want)
	}
}

func TestRunBuildsNucleiCommandWithDefaults(t *testing.T) {
	run := testRun(t, t.TempDir())
	if err := os.WriteFile(run.Path("04_surface", "attack-surface.txt"), []byte("http://example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if err := runCtx.AddArtifact("attack_surface_urls", modules.Artifact{Name: "attack_surface_urls", Type: "text", Path: "04_surface/attack-surface.txt"}); err != nil {
		t.Fatal(err)
	}
	executor := &recordingExecutor{}

	result, err := New("nuclei-test").Run(context.Background(), runCtx, executor)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("status = %q, want completed", result.Status)
	}
	if len(executor.commands) != 1 {
		t.Fatalf("command count = %d, want 1", len(executor.commands))
	}
	cmd := executor.commands[0]
	if cmd.Name != "nuclei-test" {
		t.Fatalf("command name = %q", cmd.Name)
	}
	args := strings.Join(cmd.Args, " ")
	for _, want := range []string{"-l", "04_surface/attack-surface.txt", "-severity", "low,medium,high,critical", "-rate-limit", "10", "-jsonl", "-silent"} {
		if !strings.Contains(args, want) {
			t.Errorf("args %q missing %q", args, want)
		}
	}
	if _, ok := runCtx.GetArtifact("nuclei_raw"); !ok {
		t.Fatal("nuclei_raw artifact was not published")
	}
}

func TestRunAppliesNucleiOptionsProxyAndHeaders(t *testing.T) {
	run := testRun(t, t.TempDir())
	if err := os.WriteFile(run.Path("04_surface", "attack-surface.txt"), []byte("http://example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if err := runCtx.AddArtifact("attack_surface_urls", modules.Artifact{Name: "attack_surface_urls", Type: "text", Path: "04_surface/attack-surface.txt"}); err != nil {
		t.Fatal(err)
	}
	runCtx.Nuclei = modules.NucleiOptions{
		Severity:        "critical",
		ExcludeSeverity: "info",
		Tags:            "cve,exposure",
		ExcludeTags:     "dos",
		RateLimit:       99,
		TemplatesDir:    "/tmp/templates",
	}
	runCtx.Proxy = "http://127.0.0.1:8080"
	runCtx.Headers = []string{"Cookie: session=abc"}
	executor := &recordingExecutor{}

	if _, err := New("nuclei").Run(context.Background(), runCtx, executor); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	args := strings.Join(executor.commands[0].Args, " ")
	for _, want := range []string{"-severity", "critical", "-exclude-severity", "info", "-tags", "cve,exposure", "-exclude-tags", "dos", "-rate-limit", "99", "-t", "/tmp/templates", "-proxy", "http://127.0.0.1:8080", "-H", "Cookie: session=abc"} {
		if !strings.Contains(args, want) {
			t.Errorf("args %q missing %q", args, want)
		}
	}
}

func TestRunExecutesTemplateUpdateFirst(t *testing.T) {
	run := testRun(t, t.TempDir())
	if err := os.WriteFile(run.Path("04_surface", "attack-surface.txt"), []byte("http://example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if err := runCtx.AddArtifact("attack_surface_urls", modules.Artifact{Name: "attack_surface_urls", Type: "text", Path: "04_surface/attack-surface.txt"}); err != nil {
		t.Fatal(err)
	}
	runCtx.Nuclei.UpdateTemplates = true
	executor := &recordingExecutor{}

	if _, err := New("nuclei").Run(context.Background(), runCtx, executor); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(executor.commands) != 2 {
		t.Fatalf("command count = %d, want 2 (update + scan)", len(executor.commands))
	}
	if got := executor.commands[0].Args; len(got) != 1 || got[0] != "-update-templates" {
		t.Errorf("first command = %v, want [-update-templates]", got)
	}
}

type failingExecutor struct {
	command runner.Command
}

func (e *failingExecutor) Run(_ context.Context, command runner.Command) (*runner.CommandResult, error) {
	e.command = command
	return &runner.CommandResult{Command: command, ExitCode: 1}, nil
}

func TestRunMarksExitCodeFailure(t *testing.T) {
	run := testRun(t, t.TempDir())
	if err := os.WriteFile(run.Path("04_surface", "attack-surface.txt"), []byte("http://example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if err := runCtx.AddArtifact("attack_surface_urls", modules.Artifact{Name: "attack_surface_urls", Type: "text", Path: "04_surface/attack-surface.txt"}); err != nil {
		t.Fatal(err)
	}
	executor := &failingExecutor{}

	result, err := New("nuclei").Run(context.Background(), runCtx, executor)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "failed (exit code 1)" {
		t.Fatalf("status = %q, want %q", result.Status, "failed (exit code 1)")
	}
}

func TestRunFailsWithoutAttackSurfaceArtifact(t *testing.T) {
	run := testRun(t, t.TempDir())
	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if _, err := New("nuclei").Run(context.Background(), runCtx, &recordingExecutor{}); err == nil {
		t.Fatal("expected error for missing attack_surface_urls artifact")
	}
}
