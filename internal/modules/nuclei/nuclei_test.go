package nuclei

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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

func TestRunUsesConfiguredTimeout(t *testing.T) {
	run := testRun(t, t.TempDir())
	if err := os.WriteFile(run.Path("04_surface", "attack-surface.txt"), []byte("http://example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if err := runCtx.AddArtifact("attack_surface_urls", modules.Artifact{Name: "attack_surface_urls", Type: "text", Path: "04_surface/attack-surface.txt"}); err != nil {
		t.Fatal(err)
	}
	runCtx.Nuclei.Timeout = 12 * time.Minute
	executor := &recordingExecutor{}

	if _, err := New("nuclei").Run(context.Background(), runCtx, executor); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := executor.commands[0].Timeout; got != 12*time.Minute {
		t.Fatalf("command timeout = %v, want 12m", got)
	}
}

// killedExecutor writes nuclei's partial JSONL output and then returns an
// error, simulating a timeout kill by the runner.
type killedExecutor struct {
	stdout string
}

func (e *killedExecutor) Run(_ context.Context, command runner.Command) (*runner.CommandResult, error) {
	if command.StdoutFile != "" {
		if err := os.WriteFile(command.StdoutFile, []byte(e.stdout), 0644); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("command timed out after 30m0s: signal: killed")
}

func TestRunKeepsPartialOutputWhenCommandFails(t *testing.T) {
	root := t.TempDir()
	run := testRun(t, root)
	if err := os.MkdirAll(filepath.Join(root, "06_vulns"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(run.Path("04_surface", "attack-surface.txt"), []byte("http://example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if err := runCtx.AddArtifact("attack_surface_urls", modules.Artifact{Name: "attack_surface_urls", Type: "text", Path: "04_surface/attack-surface.txt"}); err != nil {
		t.Fatal(err)
	}

	partial := `{"template-id":"exposed-git-config","host":"http://example.com","matched-at":"http://example.com/.git/config","info":{"name":"Exposed .git Config","severity":"high"}}` + "\n"
	result, err := New("nuclei").Run(context.Background(), runCtx, &killedExecutor{stdout: partial})
	if err == nil {
		t.Fatal("expected an error from the killed command")
	}
	if result == nil {
		t.Fatal("expected a partial result to be returned alongside the error")
	}
	if result.OutputFiles["nuclei_raw"] != "06_vulns/nuclei.jsonl" {
		t.Fatalf("expected nuclei_raw output file on the failed result, got %+v", result.OutputFiles)
	}
}

func TestRunFailsWithoutAttackSurfaceArtifact(t *testing.T) {
	run := testRun(t, t.TempDir())
	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if _, err := New("nuclei").Run(context.Background(), runCtx, &recordingExecutor{}); err == nil {
		t.Fatal("expected error for missing attack_surface_urls artifact")
	}
}

// writingExecutor simulates nuclei by writing its JSONL output to
// StdoutFile before returning, the same way the real executor's os/exec
// redirection would have populated it by the time Run() completes.
type writingExecutor struct {
	stdout string
}

func (e *writingExecutor) Run(_ context.Context, command runner.Command) (*runner.CommandResult, error) {
	if command.StdoutFile != "" {
		if err := os.WriteFile(command.StdoutFile, []byte(e.stdout), 0644); err != nil {
			return nil, err
		}
	}
	return &runner.CommandResult{Command: command, ExitCode: 0}, nil
}

func TestRunEmitsLiveFindingsFromNucleiOutput(t *testing.T) {
	root := t.TempDir()
	run := testRun(t, root)
	if err := os.MkdirAll(filepath.Join(root, "06_vulns"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(run.Path("04_surface", "attack-surface.txt"), []byte("http://example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if err := runCtx.AddArtifact("attack_surface_urls", modules.Artifact{Name: "attack_surface_urls", Type: "text", Path: "04_surface/attack-surface.txt"}); err != nil {
		t.Fatal(err)
	}

	var findings []modules.Finding
	runCtx.SetFindingSink(func(f modules.Finding) {
		findings = append(findings, f)
	})

	stdout := `{"template-id":"exposed-git-config","host":"http://example.com","matched-at":"http://example.com/.git/config","info":{"name":"Exposed .git Config","severity":"high"}}` + "\n" +
		`{"template-id":"or-matcher-template","host":"http://example.com","matched-at":"http://example.com/","matcher-status":false,"info":{"name":"No Match","severity":"low"}}` + "\n" +
		`not json` + "\n"

	result, err := New("nuclei-test").Run(context.Background(), runCtx, &writingExecutor{stdout: stdout})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("status = %q, want completed", result.Status)
	}

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	got := findings[0]
	if got.Module != "nuclei" || got.Severity != "high" || got.Title != "Exposed .git Config" || got.Target != "http://example.com" || got.Detail != "http://example.com/.git/config" {
		t.Fatalf("unexpected finding: %+v", got)
	}
}

func TestEmitNucleiFindingSkipsNonMatchesAndMalformedLines(t *testing.T) {
	runCtx := modules.NewRunContext("example.com", "web", false, nil)
	var findings []modules.Finding
	runCtx.SetFindingSink(func(f modules.Finding) {
		findings = append(findings, f)
	})

	emitNucleiFinding(runCtx, `not json`)
	emitNucleiFinding(runCtx, `{"template-id":"t","matcher-status":false,"host":"h","info":{"severity":"low"}}`)
	emitNucleiFinding(runCtx, `{"template-id":"t","host":"","matched-at":"","info":{"severity":"low"}}`)

	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %+v", findings)
	}

	emitNucleiFinding(runCtx, `{"template-id":"exposed-git-config","host":"h","matched-at":"h/.git","info":{"severity":"high"}}`)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %+v", findings)
	}
	if findings[0].Title != "exposed-git-config" {
		t.Fatalf("expected title to fall back to template id, got %q", findings[0].Title)
	}
}
