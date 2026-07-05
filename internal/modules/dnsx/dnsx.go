package dnsx

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
		binary = "dnsx"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string { return "dnsx" }
func (m *Module) Description() string { return "Fast multi-purpose DNS toolkit" }
func (m *Module) Requires() []string { return []string{"subdomains"} }
func (m *Module) Produces() []string { return []string{"resolved_hosts"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	inputArt, err := runCtx.MustArtifact("subdomains")
	if err != nil {
		return nil, err
	}
	inputFile := runCtx.Run.Path(inputArt.Path)

	outputFile := runCtx.Run.Path("01_subdomains", "dnsx.txt")
	stderrFile := runCtx.Run.Path("00_meta", "dnsx.stderr.log")

	cmd := runner.Command{
		Name:       m.binary,
		Args:       []string{"-l", inputFile, "-silent"},
		Timeout:    10 * time.Minute,
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

	runCtx.AddArtifact("resolved_hosts", modules.Artifact{
		Name: "resolved_hosts",
		Type: "text",
		Path: "01_subdomains/dnsx.txt",
	})

	status := "completed"
	if res.ExitCode != 0 {
		status = fmt.Sprintf("failed (exit code %d)", res.ExitCode)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: status,
		OutputFiles: map[string]string{
			"resolved_hosts": "01_subdomains/dnsx.txt",
			"dnsx_stderr":    "00_meta/dnsx.stderr.log",
		},
	}, nil
}
