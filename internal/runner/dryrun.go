package runner

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type DryRunExecutor struct{}

func NewDryRunExecutor() *DryRunExecutor {
	return &DryRunExecutor{}
}

func (e *DryRunExecutor) Run(ctx context.Context, command Command) (*CommandResult, error) {
	start := time.Now()

	fmt.Println("$", command.Name, strings.Join(command.Args, " "))

	return &CommandResult{
		Command:  command,
		ExitCode: 0,
		Duration: time.Since(start),
	}, nil
}
