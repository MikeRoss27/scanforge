package ffuf

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
	return &storage.Run{RootDir: root, CommandsLog: filepath.Join(root, "00_meta", "commands.log")}
}

func TestRequiresAliveURLs(t *testing.T) {
	if got, want := New("").Requires(), []string{"alive_urls"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Requires() = %v, want %v", got, want)
	}
}

func TestRunBuildsFFUFCommand(t *testing.T) {
	// DryRun skips the wordlist existence check so the test runs anywhere.
	run := testRun(t, t.TempDir())
	inputPath := run.Path("02_http", "httpx.txt")
	if err := os.WriteFile(inputPath, []byte("http://example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "web", true, run)
	if err := runCtx.AddArtifact("alive_urls", modules.Artifact{Name: "alive_urls", Type: "text", Path: "02_http/httpx.txt"}); err != nil {
		t.Fatal(err)
	}
	executor := &recordingExecutor{}

	result, err := New("ffuf-test").Run(context.Background(), runCtx, executor)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("status = %q, want completed", result.Status)
	}
	cmd := executor.commands[0]
	if cmd.Name != "ffuf-test" {
		t.Fatalf("command name = %q", cmd.Name)
	}
	args := strings.Join(cmd.Args, " ")
	for _, want := range []string{"-w", inputPath + ":URL", "-u", "URL/FUZZ", "-o", run.Path("05_content", "ffuf.json"), "-of", "json", "-mc", "200,301,302,403"} {
		if !strings.Contains(args, want) {
			t.Errorf("args %q missing %q", args, want)
		}
	}
	if _, ok := runCtx.GetArtifact("discovered_paths"); !ok {
		t.Fatal("discovered_paths artifact was not published")
	}
}

func TestRunAppliesWordlistAndFilterCodes(t *testing.T) {
	run := testRun(t, t.TempDir())
	if err := os.WriteFile(run.Path("02_http", "httpx.txt"), []byte("http://example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	wordlist := filepath.Join(t.TempDir(), "custom.txt")
	if err := os.WriteFile(wordlist, []byte("admin\napi\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if err := runCtx.AddArtifact("alive_urls", modules.Artifact{Name: "alive_urls", Type: "text", Path: "02_http/httpx.txt"}); err != nil {
		t.Fatal(err)
	}
	runCtx.Ffuf = modules.FfufOptions{Wordlist: wordlist, FilterCodes: "404,500"}
	executor := &recordingExecutor{}

	if _, err := New("ffuf").Run(context.Background(), runCtx, executor); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	args := strings.Join(executor.commands[0].Args, " ")
	for _, want := range []string{"-w", wordlist + ":FUZZ", "-fc", "404,500"} {
		if !strings.Contains(args, want) {
			t.Errorf("args %q missing %q", args, want)
		}
	}
}

func TestRunRequiresExistingWordlistOutsideDryRun(t *testing.T) {
	run := testRun(t, t.TempDir())
	if err := os.WriteFile(run.Path("02_http", "httpx.txt"), []byte("http://example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if err := runCtx.AddArtifact("alive_urls", modules.Artifact{Name: "alive_urls", Type: "text", Path: "02_http/httpx.txt"}); err != nil {
		t.Fatal(err)
	}
	if _, err := New("ffuf").Run(context.Background(), runCtx, &recordingExecutor{}); err == nil {
		t.Fatal("expected error for missing wordlist outside dry-run")
	}
}
