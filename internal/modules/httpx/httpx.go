package httpx

import (
	"context"
	"fmt"
	"os"
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
		binary = "httpx"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string {
	return "httpx"
}

func (m *Module) Run(ctx context.Context, scanRun *storage.Run, executor runner.Executor, target string) (*modules.Result, error) {
	inputFile := scanRun.Path("01_subdomains", "subfinder.txt")
	rawOutputFile := scanRun.Path("02_http", "httpx.jsonl")
	aliveOutputFile := scanRun.Path("02_http", "alive.txt")
	stderrFile := scanRun.Path("00_meta", "httpx.stderr.log")

	cmd := runner.Command{
		Name: m.binary,
		Args: []string{
			"-l", inputFile,
			"-silent",
			"-json",
			"-status-code",
			"-title",
			"-tech-detect",
		},
		Timeout:    10 * time.Minute,
		StdoutFile: rawOutputFile,
		StderrFile: stderrFile,
	}

	if err := runner.AppendCommandLog(scanRun.CommandsLog, cmd); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	if _, err := executor.Run(ctx, cmd); err != nil {
		return nil, fmt.Errorf("failed to run command %q: %w", cmd.Name, err)
	}

	if _, err := os.Stat(rawOutputFile); err == nil {
		if _, err := WriteAliveURLs(rawOutputFile, aliveOutputFile); err != nil {
			return nil, fmt.Errorf("failed to write alive URLs: %w", err)
		}
	}

	return &modules.Result{
		Name: m.Name(),
		OutputFiles: map[string]string{
			"httpx_raw":    "02_http/httpx.jsonl",
			"alive_urls":   "02_http/alive.txt",
			"httpx_stderr": "00_meta/httpx.stderr.log",
		},
	}, nil
}
