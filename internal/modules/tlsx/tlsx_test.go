package tlsx

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

type recordingExecutor struct{ command runner.Command }

func (e *recordingExecutor) Run(_ context.Context, command runner.Command) (*runner.CommandResult, error) {
	e.command = command
	return &runner.CommandResult{Command: command}, nil
}

func TestRunConsumesAliveURLs(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "00_meta"), 0755); err != nil {
		t.Fatal(err)
	}
	run := &storage.Run{RootDir: root, CommandsLog: filepath.Join(root, "00_meta", "commands.log")}
	runCtx := modules.NewRunContext("example.com", "safe", true, run)
	if err := runCtx.AddArtifact("alive_urls", modules.Artifact{
		Name: "alive_urls", Type: "text", Path: "02_http/alive.txt",
	}); err != nil {
		t.Fatal(err)
	}
	executor := &recordingExecutor{}
	if _, err := New("tlsx-test").Run(context.Background(), runCtx, executor); err != nil {
		t.Fatal(err)
	}
	if executor.command.Name != "tlsx-test" || len(executor.command.Args) < 4 || executor.command.Args[0] != "-l" {
		t.Fatalf("unexpected tlsx command: %+v", executor.command)
	}
	if _, ok := runCtx.GetArtifact("tls_raw"); !ok {
		t.Fatal("tls_raw artifact was not published")
	}
}
