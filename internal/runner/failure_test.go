package runner

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestClassifyFailureMissingBinary(t *testing.T) {
	_, err := NewRealExecutor(false).Run(context.Background(), Command{
		Name: "scanforge-definitely-not-a-real-binary-xyz",
	})
	if err == nil {
		t.Fatal("expected an error for a missing binary")
	}
	if got := ClassifyFailure(err); got != FailureNotFound {
		t.Fatalf("ClassifyFailure(%v) = %q, want %q", err, got, FailureNotFound)
	}
	// A module wrapping the executor's error with its own context must not
	// lose the classification: errors.As still has to reach the exec.Error.
	wrapped := fmt.Errorf("failed to run command %q: %w", "scanforge-definitely-not-a-real-binary-xyz", err)
	if got := ClassifyFailure(wrapped); got != FailureNotFound {
		t.Fatalf("ClassifyFailure(wrapped) = %q, want %q", got, FailureNotFound)
	}
}

func TestClassifyFailureTimeout(t *testing.T) {
	_, err := NewRealExecutor(false).Run(context.Background(), Command{
		Name:    "sh",
		Args:    []string{"-c", "sleep 5"},
		Timeout: 50 * time.Millisecond,
	})
	if got := ClassifyFailure(err); got != FailureTimeout {
		t.Fatalf("ClassifyFailure(%v) = %q, want %q", err, got, FailureTimeout)
	}
	wrapped := fmt.Errorf("module %q timed out after %s: %w", "nuclei", 50*time.Millisecond, err)
	if got := ClassifyFailure(wrapped); got != FailureTimeout {
		t.Fatalf("ClassifyFailure(wrapped) = %q, want %q", got, FailureTimeout)
	}
}

func TestClassifyFailureCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	timer := time.AfterFunc(50*time.Millisecond, cancel)
	defer timer.Stop()
	_, err := NewRealExecutor(false).Run(ctx, Command{
		Name: "sh", Args: []string{"-c", "exec sleep 5"},
	})
	if got := ClassifyFailure(err); got != FailureCanceled {
		t.Fatalf("ClassifyFailure(%v) = %q, want %q", err, got, FailureCanceled)
	}
}

func TestClassifyFailureUnknown(t *testing.T) {
	if got := ClassifyFailure(errors.New("module \"naabu\" failed: exit code 2")); got != FailureUnknown {
		t.Fatalf("ClassifyFailure(generic) = %q, want %q", got, FailureUnknown)
	}
}
