package runner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/ui"
)

type DryRunExecutor struct {
	verbose     bool
	commandSink CommandSink
}

// NewDryRunExecutor records commands without running them. When a command
// sink is installed it owns the command transcript (the scan console prints
// it); standalone callers without a sink get the historical stdout lines.
func NewDryRunExecutor(verbose bool, opts ...ExecutorOption) *DryRunExecutor {
	cfg := applyOptions(opts)
	return &DryRunExecutor{verbose: verbose, commandSink: cfg.commandSink}
}

func (e *DryRunExecutor) Run(ctx context.Context, command Command) (*CommandResult, error) {
	start := time.Now()

	result := &CommandResult{
		Command:  command,
		ExitCode: 0,
		Duration: time.Since(start),
	}

	if e.commandSink != nil {
		e.commandSink(command, result, nil)
		return result, nil
	}

	fmt.Println(ui.CommandLine(command.Name + " " + strings.Join(command.Args, " ")))
	if e.verbose {
		if command.StdoutFile != "" {
			fmt.Println("stdout:", command.StdoutFile)
		}
		if command.StderrFile != "" {
			fmt.Println("stderr:", command.StderrFile)
		}
	}
	return result, nil
}
