package katana

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

func TestRunBuildsKatanaCommandWithProxyAndHeaders(t *testing.T) {
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
	runCtx.Headers = []string{"Cookie: session=abc"}
	executor := &recordingExecutor{}

	result, err := New("katana-test").Run(context.Background(), runCtx, executor)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("status = %q, want completed", result.Status)
	}
	cmd := executor.commands[0]
	args := strings.Join(cmd.Args, " ")
	for _, want := range []string{"-list", inputPath, "-silent", "-depth", "2", "-proxy", "http://127.0.0.1:8080", "-H", "Cookie: session=abc"} {
		if !strings.Contains(args, want) {
			t.Errorf("args %q missing %q", args, want)
		}
	}
	if _, ok := runCtx.GetArtifact("crawled_urls"); !ok {
		t.Fatal("crawled_urls artifact was not published")
	}
}
