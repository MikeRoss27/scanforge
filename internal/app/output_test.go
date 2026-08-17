package app

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

// A module the orchestrator marked "skipped" (failed upstream dependency)
// emits ModuleDoneEvent{Status: "skipped", Failed: false, Dur: 0}; it must
// never render like a success.
func TestPrintModuleResultSkippedNotShownAsSuccess(t *testing.T) {
	var buf bytes.Buffer
	printModuleResult(&buf, orchestrator.ModuleDoneEvent{Name: "nmap", Status: "skipped"})

	line := buf.String()
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

func TestPrintModuleResultAbortedShowsStatus(t *testing.T) {
	var buf bytes.Buffer
	printModuleResult(&buf, orchestrator.ModuleDoneEvent{Name: "nuclei", Status: "aborted"})

	line := buf.String()
	if strings.Contains(line, "✓") {
		t.Errorf("aborted module rendered with a success mark: %q", line)
	}
	if !strings.Contains(line, "aborted") {
		t.Errorf("aborted status not surfaced: %q", line)
	}
}

func TestPrintModuleResultFailedShowsExitStatus(t *testing.T) {
	var buf bytes.Buffer
	printModuleResult(&buf, orchestrator.ModuleDoneEvent{
		Name: "naabu", Status: "failed (exit code 2)", Failed: true, Dur: 3 * time.Second,
	})

	line := buf.String()
	if !strings.Contains(line, "✗") {
		t.Errorf("failed module missing failure mark: %q", line)
	}
	if !strings.Contains(line, "failed (exit code 2)") {
		t.Errorf("failure status not surfaced: %q", line)
	}
}

func TestPrintModuleResultCompletedKeepsSummary(t *testing.T) {
	var buf bytes.Buffer
	printModuleResult(&buf, orchestrator.ModuleDoneEvent{
		Name: "subfinder", Status: "completed", Dur: 2 * time.Second, Summary: "8 subdomains",
	})

	line := buf.String()
	if !strings.Contains(line, "✓") || !strings.Contains(line, "8 subdomains") {
		t.Errorf("completed line lost mark or summary: %q", line)
	}
	if strings.Contains(line, "skipped") || strings.Contains(line, "aborted") {
		t.Errorf("completed line gained a bogus status: %q", line)
	}
}

func TestWrapModuleListKeepsLinesBounded(t *testing.T) {
	items := make([]string, 0, 17)
	for _, name := range []string{
		"dnsx", "httpx", "naabu", "nmap", "tlsx", "whatweb", "wafw00f", "katana",
		"jssecrets", "jsverify", "attacksurface", "techcve", "httpcheck",
		"payloadgen", "screenshot", "ffuf", "nuclei",
	} {
		items = append(items, name+" (skipped)")
	}

	got := wrapModuleList(items)
	if !strings.Contains(got, "\n") {
		t.Fatalf("expected the long list to wrap, got %q", got)
	}
	for _, line := range strings.Split(got, "\n") {
		// Continuation lines carry the 10-space kv alignment indent on top
		// of the content budget.
		if len(strings.TrimSpace(line)) > 66 {
			t.Errorf("wrapped line exceeds the width budget: %q", line)
		}
	}
	for _, name := range []string{"dnsx", "nuclei", "katana"} {
		if !strings.Contains(got, name) {
			t.Errorf("wrapped list lost module %q: %q", name, got)
		}
	}
}

func TestWrapModuleListSingleLineUnchanged(t *testing.T) {
	got := wrapModuleList([]string{"naabu (failed)"})
	if got != "naabu (failed)" {
		t.Errorf("single short item must not be altered, got %q", got)
	}
}

func TestPrintRunSummaryBoxSeparatesSkippedFromFailed(t *testing.T) {
	now := time.Now().Format(time.RFC3339)
	scanRun := &storage.Run{
		RootDir: t.TempDir(),
		Manifest: storage.RunManifest{
			Status:      "partial",
			StartedAt:   now,
			CompletedAt: now,
		},
	}
	results := []*modules.Result{
		{Name: "subfinder", Status: "completed"},
		{Name: "naabu", Status: "failed"},
		{Name: "nmap", Status: "skipped"},
		{Name: "nuclei", Status: "aborted"},
	}

	var buf bytes.Buffer
	printRunSummaryBox(&buf, scanRun, results, nil)
	out := buf.String()

	if !strings.Contains(out, "SKIPPED") {
		t.Fatalf("summary box has no SKIPPED line:\n%s", out)
	}

	var failedLine, skippedLine string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "FAILED") {
			failedLine = line
		}
		if strings.Contains(line, "SKIPPED") {
			skippedLine = line
		}
	}
	if !strings.Contains(failedLine, "naabu") || strings.Contains(failedLine, "nmap") || strings.Contains(failedLine, "nuclei") {
		t.Errorf("FAILED line mixes non-failures with failures: %q", failedLine)
	}
	if !strings.Contains(skippedLine, "nmap") || !strings.Contains(skippedLine, "nuclei") {
		t.Errorf("SKIPPED line misses skipped/aborted modules: %q", skippedLine)
	}
}
