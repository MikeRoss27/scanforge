package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/MikeRoss27/scanforge/internal/orchestrator"
)

// A module the orchestrator marked "skipped" (failed upstream dependency)
// emits ModuleDoneEvent{Status: "skipped", Failed: false, Dur: 0}; it must
// never render like a success.
func TestFormatModuleResultSkippedNotShownAsSuccess(t *testing.T) {
	line := FormatEvent(orchestrator.ModuleDoneEvent{Name: "nmap", Status: "skipped"})
	if strings.Contains(line, "✓") {
		t.Errorf("skipped module rendered with a success mark: %q", line)
	}
	if !strings.Contains(line, "nmap") {
		t.Errorf("module name missing: %q", line)
	}
	if !strings.Contains(line, "skipped") {
		t.Errorf("skipped status not surfaced: %q", line)
	}
}

func TestFormatModuleResultAbortedShowsStatus(t *testing.T) {
	line := FormatEvent(orchestrator.ModuleDoneEvent{Name: "nuclei", Status: "aborted"})
	if strings.Contains(line, "✓") {
		t.Errorf("aborted module rendered with a success mark: %q", line)
	}
	if !strings.Contains(line, "aborted") {
		t.Errorf("aborted status not surfaced: %q", line)
	}
}

func TestFormatModuleResultFailedShowsExitStatus(t *testing.T) {
	line := FormatEvent(orchestrator.ModuleDoneEvent{
		Name: "naabu", Status: "failed (exit code 2)", Failed: true, Dur: 3 * time.Second,
	})
	if !strings.Contains(line, "✗") {
		t.Errorf("failed module missing failure mark: %q", line)
	}
	if !strings.Contains(line, "failed (exit code 2)") {
		t.Errorf("failure status not surfaced: %q", line)
	}
}

func TestFormatModuleResultCompletedKeepsSummary(t *testing.T) {
	line := FormatEvent(orchestrator.ModuleDoneEvent{
		Name: "subfinder", Status: "completed", Dur: 2 * time.Second, Summary: "8 subdomains",
	})
	if !strings.Contains(line, "✓") || !strings.Contains(line, "8 subdomains") {
		t.Errorf("completed line lost mark or summary: %q", line)
	}
	if strings.Contains(line, "skipped") || strings.Contains(line, "aborted") {
		t.Errorf("completed line gained a bogus status: %q", line)
	}
}
