package runner

import (
	"context"
	"testing"
	"time"
)

func TestRealExecutorZeroExit(t *testing.T) {
	res, err := NewRealExecutor(false).Run(context.Background(), Command{
		Name: "sh",
		Args: []string{"-c", "exit 0"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", res.ExitCode)
	}
}

func TestRealExecutorNonZeroExitRecordsExitCodeWithoutError(t *testing.T) {
	res, err := NewRealExecutor(false).Run(context.Background(), Command{
		Name: "sh",
		Args: []string{"-c", "exit 3"},
	})
	if err != nil {
		t.Fatalf("non-zero exit must not be reported as an error, got: %v", err)
	}
	if res.ExitCode != 3 {
		t.Fatalf("exit code = %d, want 3", res.ExitCode)
	}
}

func TestRealExecutorMissingBinaryReturnsError(t *testing.T) {
	_, err := NewRealExecutor(false).Run(context.Background(), Command{
		Name: "scanforge-definitely-not-a-real-binary-xyz",
	})
	if err == nil {
		t.Fatal("expected an error for a missing binary")
	}
}

func TestRealExecutorTimeoutReturnsError(t *testing.T) {
	_, err := NewRealExecutor(false).Run(context.Background(), Command{
		Name:    "sh",
		Args:    []string{"-c", "sleep 5"},
		Timeout: 50 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("expected an error when the command times out")
	}
}
