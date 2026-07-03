package nuclei

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
		binary = "nuclei"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string {
	return "nuclei"
}

func (m *Module) Run(ctx context.Context, scanRun *storage.Run, executor runner.Executor, target string) (*modules.Result, error) {
	inputFile := scanRun.Path("02_http", "alive.txt")
	rawOutputFile := scanRun.Path("06_vulns", "nuclei.jsonl")
	findingsFile := scanRun.Path("06_vulns", "findings.json")
	stderrFile := scanRun.Path("00_meta", "nuclei.stderr.log")

	cmd := runner.Command{
		Name: m.binary,
		Args: []string{
			"-l", inputFile,
			"-severity", "low,medium,high,critical",
			"-rate-limit", "10",
			"-jsonl",
		},
		Timeout:    30 * time.Minute,
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
		if _, err := WriteFindingsJSON(rawOutputFile, findingsFile); err != nil {
			return nil, fmt.Errorf("failed to write findings JSON: %w", err)
		}
	}

	return &modules.Result{
		Name: m.Name(),
		OutputFiles: map[string]string{
			"nuclei_raw":    "06_vulns/nuclei.jsonl",
			"findings":      "06_vulns/findings.json",
			"nuclei_stderr": "00_meta/nuclei.stderr.log",
		},
	}, nil
}
