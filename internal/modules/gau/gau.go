package gau

import (
	"context"
	"fmt"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

type Module struct {
	binary string
}

func New(binary string) *Module {
	if binary == "" {
		binary = "gau"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string        { return "gau" }
func (m *Module) Description() string { return "Passive historical URL discovery" }
func (m *Module) Requires() []string  { return nil }
func (m *Module) Produces() []string  { return []string{"historical_urls"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	outputFile := runCtx.Run.Path("05_content", "gau.txt")
	stderrFile := runCtx.Run.Path("00_meta", "gau.stderr.log")
	cmd := runner.Command{
		Name: m.binary,
		Args: []string{
			"--subs",
			"--threads", "5",
			"--blacklist", "png,jpg,jpeg,gif,svg,woff,woff2,ico",
			runCtx.Target,
		},
		Timeout:    20 * time.Minute,
		StdoutFile: outputFile,
		StderrFile: stderrFile,
	}
	cmd.Args = append(cmd.Args, runCtx.ProxyArgs("--proxy")...)

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, cmd); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}
	if _, err := executor.Run(ctx, cmd); err != nil {
		return nil, fmt.Errorf("failed to run command %q: %w", cmd.Name, err)
	}
	if err := runCtx.AddArtifact("historical_urls", modules.Artifact{
		Name: "historical_urls",
		Type: "text",
		Path: "05_content/gau.txt",
	}); err != nil {
		return nil, fmt.Errorf("failed to publish historical URLs: %w", err)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: "completed",
		OutputFiles: map[string]string{
			"historical_urls": "05_content/gau.txt",
			"gau_stderr":      "00_meta/gau.stderr.log",
		},
	}, nil
}
