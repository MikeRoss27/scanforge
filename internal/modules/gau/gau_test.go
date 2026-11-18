package gau

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

type recordingExecutor struct {
	command  runner.Command
	exitCode int
}

func (e *recordingExecutor) Run(_ context.Context, command runner.Command) (*runner.CommandResult, error) {
	e.command = command
	return &runner.CommandResult{Command: command, ExitCode: e.exitCode}, nil
}

func TestRunUsesRootTargetAndPublishesHistoricalURLs(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "00_meta"), 0755); err != nil {
		t.Fatal(err)
	}
	run := &storage.Run{RootDir: root, CommandsLog: filepath.Join(root, "00_meta", "commands.log")}
	runCtx := modules.NewRunContext("https://Example.COM:443/path?query=1", "recon", true, run)
	executor := &recordingExecutor{}
	if _, err := New("gau-test").Run(context.Background(), runCtx, executor); err != nil {
		t.Fatal(err)
	}
	if executor.command.Name != "gau-test" || executor.command.Args[len(executor.command.Args)-1] != "example.com" {
		t.Fatalf("unexpected gau command: %+v", executor.command)
	}
	if _, ok := runCtx.GetArtifact("historical_urls"); !ok {
		t.Fatal("historical_urls artifact was not published")
	}
}

func TestRunDoesNotPublishArtifactOnNonZeroExit(t *testing.T) {
	root := t.TempDir()
	run := &storage.Run{RootDir: root, CommandsLog: filepath.Join(root, "commands.log")}
	runCtx := modules.NewRunContext("example.com", "full", true, run)
	_, err := New("").Run(context.Background(), runCtx, &recordingExecutor{exitCode: 2})
	if err == nil {
		t.Fatal("expected gau failure")
	}
	if _, ok := runCtx.GetArtifact("historical_urls"); ok {
		t.Fatal("failed gau must not publish historical_urls")
	}
}
