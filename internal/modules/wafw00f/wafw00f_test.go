package wafw00f

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
	if err := os.MkdirAll(filepath.Join(root, "04_web"), 0755); err != nil {
		t.Fatal(err)
	}
	return &storage.Run{RootDir: root, CommandsLog: filepath.Join(root, "00_meta", "commands.log")}
}

func TestRequiresAliveURLs(t *testing.T) {
	if got, want := New("").Requires(), []string{"alive_urls"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Requires() = %v, want %v", got, want)
	}
}

// writingExecutor records commands like recordingExecutor, and additionally
// writes fixed text to the command's StdoutFile, so tests can exercise
// detectWAFNames against a realistic wafw00f transcript.
type writingExecutor struct {
	commands []runner.Command
	stdout   string
}

func (e *writingExecutor) Run(_ context.Context, command runner.Command) (*runner.CommandResult, error) {
	e.commands = append(e.commands, command)
	if command.StdoutFile != "" {
		if err := os.WriteFile(command.StdoutFile, []byte(e.stdout), 0644); err != nil {
			return nil, err
		}
	}
	return &runner.CommandResult{Command: command, ExitCode: 0}, nil
}

func TestRunRecordsWAFInfoWhenDetected(t *testing.T) {
	run := testRun(t, t.TempDir())
	inputPath := run.Path("02_http", "httpx.txt")
	if err := os.WriteFile(inputPath, []byte("http://example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if err := runCtx.AddArtifact("alive_urls", modules.Artifact{Name: "alive_urls", Type: "text", Path: "02_http/httpx.txt"}); err != nil {
		t.Fatal(err)
	}
	executor := &writingExecutor{stdout: "[*] Checking https://example.com\n[+] The site https://example.com is behind Cloudflare WAF.\n[~] Number of requests: 2\n"}

	if _, err := New("wafw00f-test").Run(context.Background(), runCtx, executor); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	info := runCtx.GetWAFInfo()
	if !info.Detected {
		t.Fatal("WAF should be detected")
	}
	if len(info.Names) != 1 || info.Names[0] != "Cloudflare" {
		t.Fatalf("Names = %v, want [Cloudflare]", info.Names)
	}
}

func TestRunLeavesWAFUndetectedWhenNoneReported(t *testing.T) {
	run := testRun(t, t.TempDir())
	inputPath := run.Path("02_http", "httpx.txt")
	if err := os.WriteFile(inputPath, []byte("http://example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if err := runCtx.AddArtifact("alive_urls", modules.Artifact{Name: "alive_urls", Type: "text", Path: "02_http/httpx.txt"}); err != nil {
		t.Fatal(err)
	}
	executor := &writingExecutor{stdout: "[*] Checking https://example.com\n[-] No WAF detected by the generic detection\n"}

	if _, err := New("wafw00f-test").Run(context.Background(), runCtx, executor); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if info := runCtx.GetWAFInfo(); info.Detected {
		t.Fatalf("WAFInfo = %+v, want undetected", info)
	}
}

func TestRunBuildsWafw00fCommandWithProxy(t *testing.T) {
	run := testRun(t, t.TempDir())
	inputPath := run.Path("02_http", "httpx.txt")
	if err := os.WriteFile(inputPath, []byte("http://example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if err := runCtx.AddArtifact("alive_urls", modules.Artifact{Name: "alive_urls", Type: "text", Path: "02_http/httpx.txt"}); err != nil {
		t.Fatal(err)
	}
	runCtx.Proxy = "http://127.0.0.1:8080"
	executor := &recordingExecutor{}

	result, err := New("wafw00f-test").Run(context.Background(), runCtx, executor)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("status = %q, want completed", result.Status)
	}
	cmd := executor.commands[0]
	args := strings.Join(cmd.Args, " ")
	for _, want := range []string{"-i", inputPath, "-p", "http://127.0.0.1:8080"} {
		if !strings.Contains(args, want) {
			t.Errorf("args %q missing %q", args, want)
		}
	}
	if _, ok := runCtx.GetArtifact("waf_raw"); !ok {
		t.Fatal("waf_raw artifact was not published")
	}
}
