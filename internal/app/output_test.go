package app

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

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
