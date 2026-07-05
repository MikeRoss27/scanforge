package subfinder

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
		binary = "subfinder"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string {
	return "subfinder"
}

func (m *Module) Description() string {
	return "Fast passive subdomain enumeration tool"
}

func (m *Module) Requires() []string {
	return nil // No required artifacts, uses Target
}

func (m *Module) Produces() []string {
	return []string{"subdomains"}
}

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	outputFile := runCtx.Run.Path("01_subdomains", "subfinder.txt")
	stderrFile := runCtx.Run.Path("00_meta", "subfinder.stderr.log")

	cmd := runner.Command{
		Name:       m.binary,
		Args:       []string{"-d", runCtx.Target, "-silent"},
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

	runCtx.AddArtifact("subdomains", modules.Artifact{
		Name: "subdomains",
		Type: "text",
		Path: "01_subdomains/subfinder.txt",
	})

	status := "completed"
	if res.ExitCode != 0 {
		status = fmt.Sprintf("failed (exit code %d)", res.ExitCode)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: status,
		OutputFiles: map[string]string{
			"subfinder":        "01_subdomains/subfinder.txt",
			"subfinder_stderr": "00_meta/subfinder.stderr.log",
		},
	}, nil
}
