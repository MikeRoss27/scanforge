package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

type RealExecutor struct {
	verbose bool
}

func NewRealExecutor(verbose bool) *RealExecutor {
	return &RealExecutor{verbose: verbose}
}

func (e *RealExecutor) Run(ctx context.Context, command Command) (*CommandResult, error) {
	start := time.Now()

	timeout := command.Timeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}

	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, command.Name, command.Args...)
	cmd.Dir = command.Dir

	if len(command.Env) > 0 {
		cmd.Env = append(os.Environ(), command.Env...)
	}

	if command.StdoutFile != "" {
		stdout, err := os.Create(command.StdoutFile)
		if err != nil {
			return nil, err
		}
		defer stdout.Close()
		cmd.Stdout = stdout
	} else {
		cmd.Stdout = os.Stdout
	}

	if command.StderrFile != "" {
		stderr, err := os.Create(command.StderrFile)
		if err != nil {
			return nil, err
		}
		defer stderr.Close()
		cmd.Stderr = stderr
	} else {
		cmd.Stderr = os.Stderr
	}

	err := cmd.Run()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, err
		}
	}

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
		ExitCode: exitCode,
		Duration: time.Since(start),
	}, err
}
