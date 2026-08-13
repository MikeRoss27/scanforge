package runner

import (
	"context"
	"errors"
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
		defer func() { _ = stdout.Close() }()
		cmd.Stdout = stdout
	} else {
		cmd.Stdout = os.Stdout
	}

	if command.StderrFile != "" {
		stderr, err := os.Create(command.StderrFile)
		if err != nil {
			return nil, err
		}
		defer func() { _ = stderr.Close() }()
		cmd.Stderr = stderr
	} else {
		cmd.Stderr = os.Stderr
	}

	err := cmd.Run()

	// A context deadline kill surfaces as "signal: killed", which hides what
	// actually went wrong. Translate timeouts (and only timeouts) into a
	// message operators can act on.
	if err != nil && cmdCtx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("command timed out after %s: %w", timeout, err)
	}

	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		// A non-zero exit code is not a failure of the executor: tools like
		// nmap legitimately exit 1 when a host is down or has no open ports.
		// Record the exit code and let the module decide. Real failures
		// (binary missing, timeout, cancellation) still surface as errors.
		if errors.As(err, &exitErr) && cmdCtx.Err() == nil {
			exitCode = exitErr.ExitCode()
			err = nil
		}
	}

	if e.verbose {
		// Diagnostics go to stderr so they never corrupt a Bubble Tea render
		// loop that owns stdout.
		if command.StdoutFile != "" {
			fmt.Fprintln(os.Stderr, "stdout:", command.StdoutFile)
		}
		if command.StderrFile != "" {
			fmt.Fprintln(os.Stderr, "stderr:", command.StderrFile)
		}
	}

	return &CommandResult{
		Command:  command,
		ExitCode: exitCode,
		Duration: time.Since(start),
	}, err
}
