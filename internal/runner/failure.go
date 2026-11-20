package runner

import (
	"context"
	"errors"
	"os/exec"
)

// FailureKind classifies why Executor.Run returned a non-nil error, so
// callers can react to *why* a tool failed instead of only *that* it did.
//
// A non-zero exit code is deliberately not a FailureKind: RealExecutor
// already treats it as a normal outcome (CommandResult.ExitCode) rather
// than an error, since tools like nmap legitimately exit non-zero for a
// down host. FailureKind only covers the executor-level failures where the
// tool's own result was never produced at all.
type FailureKind string

const (
	// FailureUnknown covers any error not classified below: a real
	// failure, but not one with a more specific, actionable hint.
	FailureUnknown FailureKind = "unknown"
	// FailureNotFound means the binary itself could not be located on
	// PATH (or exists but isn't executable) — nothing was ever launched.
	FailureNotFound FailureKind = "not_found"
	// FailureTimeout means the command's own Timeout elapsed and it was
	// killed mid-run.
	FailureTimeout FailureKind = "timeout"
	// FailureCanceled means the run was aborted by the caller (Ctrl-C, or
	// the orchestrator tearing down after an earlier failure), not by the
	// tool itself failing.
	FailureCanceled FailureKind = "canceled"
)

// ClassifyFailure inspects err's wrapped chain and returns the most
// specific FailureKind it can determine. It works whether err is the raw
// error RealExecutor.Run returned or a module/orchestrator's
// fmt.Errorf("...: %w", err) wrapping of it, since both preserve the chain
// errors.Is/errors.As walk. Call it only when err != nil.
func ClassifyFailure(err error) FailureKind {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return FailureTimeout
	case errors.Is(err, context.Canceled):
		return FailureCanceled
	}
	var execErr *exec.Error
	if errors.As(err, &execErr) {
		return FailureNotFound
	}
	return FailureUnknown
}
