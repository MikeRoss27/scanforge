package subfinder

import (
	"context"
	"fmt"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
	"github.com/MikeRoss27/scanforge/internal/storage"
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

func (m *Module) Run(ctx context.Context, scanRun *storage.Run, executor runner.Executor, target string) (*modules.Result, error) {
	cmd := runner.Command{
		Name:       m.binary,
		Args:       []string{"-d", target, "-silent"},
		Timeout:    10 * time.Minute,
		StdoutFile: scanRun.Path("01_subdomains", "subfinder.txt"),
		StderrFile: scanRun.Path("00_meta", "subfinder.stderr.log"),
	}

	if err := runner.AppendCommandLog(scanRun.CommandsLog, cmd); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	if _, err := executor.Run(ctx, cmd); err != nil {
		return nil, fmt.Errorf("failed to run command %q: %w", cmd.Name, err)
	}

	return &modules.Result{
		Name: m.Name(),
		OutputFiles: map[string]string{
			"subfinder":        "01_subdomains/subfinder.txt",
			"subfinder_stderr": "00_meta/subfinder.stderr.log",
		},
	}, nil
}
