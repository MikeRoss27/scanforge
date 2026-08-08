package runner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/ui"
)

type DryRunExecutor struct {
	verbose bool
}

func NewDryRunExecutor(verbose bool) *DryRunExecutor {
	return &DryRunExecutor{verbose: verbose}
}

func (e *DryRunExecutor) Run(ctx context.Context, command Command) (*CommandResult, error) {
	start := time.Now()

	fmt.Println(ui.CommandLine(command.Name + " " + strings.Join(command.Args, " ")))

	if e.verbose {
		if command.StdoutFile != "" {
			fmt.Println("stdout:", command.StdoutFile)
		}
		if command.StderrFile != "" {
			fmt.Println("stderr:", command.StderrFile)
		}
	}

	return &CommandResult{
		Command:  command,
		ExitCode: 0,
		Duration: time.Since(start),
	}, nil
}
