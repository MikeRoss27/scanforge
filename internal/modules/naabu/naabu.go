package naabu

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
		binary = "naabu"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string { return "naabu" }
func (m *Module) Description() string { return "Fast port scanner" }
func (m *Module) Requires() []string { return []string{"resolved_hosts"} }
func (m *Module) Produces() []string { return []string{"open_ports"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	inputArt, err := runCtx.MustArtifact("resolved_hosts")
	if err != nil {
		return nil, err
	}
	inputFile := runCtx.Run.Path(inputArt.Path)

	outputFile := runCtx.Run.Path("03_ports", "naabu.txt")
	stderrFile := runCtx.Run.Path("00_meta", "naabu.stderr.log")

	cmd := runner.Command{
		Name:       m.binary,
		Args:       []string{"-l", inputFile, "-silent"},
		Timeout:    30 * time.Minute,
		StdoutFile: outputFile,
		StderrFile: stderrFile,
	}

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, cmd); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	res, err := executor.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run command %q: %w", cmd.Name, err)
	}

	runCtx.AddArtifact("open_ports", modules.Artifact{
		Name: "open_ports",
		Type: "text",
		Path: "03_ports/naabu.txt",
	})

	status := "completed"
	if res.ExitCode != 0 {
		status = fmt.Sprintf("failed (exit code %d)", res.ExitCode)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: status,
		OutputFiles: map[string]string{
			"open_ports":   "03_ports/naabu.txt",
			"naabu_stderr": "00_meta/naabu.stderr.log",
		},
	}, nil
}
