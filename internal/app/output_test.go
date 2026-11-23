package app

import (
	"testing"

	"github.com/MikeRoss27/scanforge/internal/report"
)

// TestFindingTypesByReportMatchesSeverityCounts guards against the recap
// bug where the summary's severity totals (countBySeverity) and its
// "Finding types" breakdown read different data: a report with N
// vulnerabilities must produce exactly N finding-type occurrences in total,
// and every severity present in countBySeverity must appear here too.
func TestFindingTypesByReportMatchesSeverityCounts(t *testing.T) {
	rep := report.NewReport("example.com", "full")
	asset := rep.GetOrCreateAsset("example.com")
	asset.Vulnerabilities = []*report.Vulnerability{
		{Source: "jssecrets", Title: "Internal host/IP referenced in JavaScript", Severity: "low"},
		{Source: "jssecrets", Title: "Hardcoded API key", Severity: "info"},
		{Source: "techcve", Title: "Outdated nginx", Severity: "info"},
	}

	types := findingTypesByReport(rep)
	severities := countBySeverity(rep)

	var total int
	for _, ft := range types {
		total += ft.Count
	}
	if total != 3 {
		t.Fatalf("total finding-type occurrences = %d, want 3", total)
	}

	bySeverity := map[string]int{}
	for _, ft := range types {
		bySeverity[ft.Severity] += ft.Count
	}
	for severity, want := range severities {
		if got := bySeverity[severity]; got != want {
			t.Errorf("severity %q: findingTypesByReport = %d, countBySeverity = %d (summary would show mismatched totals)", severity, got, want)
		}
	}
}

func TestFindingTypesByReportGroupsIdenticalFindings(t *testing.T) {
	rep := report.NewReport("example.com", "full")
	for _, host := range []string{"a.example.com", "b.example.com"} {
		asset := rep.GetOrCreateAsset(host)
		asset.Vulnerabilities = []*report.Vulnerability{
			{Source: "jssecrets", Title: "Internal host/IP referenced in JavaScript", Severity: "low"},
		}
	}

	types := findingTypesByReport(rep)
	if len(types) != 1 {
		t.Fatalf("got %d distinct finding types, want 1 (same module/title/severity across hosts)", len(types))
	}
	if types[0].Count != 2 {
		t.Fatalf("Count = %d, want 2", types[0].Count)
	}
}
