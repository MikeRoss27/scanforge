package report

import (
	"strings"
	"testing"
)

func TestFormatFindingsTableEmpty(t *testing.T) {
	if got := FormatFindingsTable(nil); got != "" {
		t.Errorf("expected empty table for nil report, got %q", got)
	}
	rep := NewReport("example.com", "web")
	if got := FormatFindingsTable(rep); got != "" {
		t.Errorf("expected empty table for report without findings, got %q", got)
	}
}

func TestFormatFindingsTableSortsBySeverity(t *testing.T) {
	rep := NewReport("example.com", "web")
	asset := rep.GetOrCreateAsset("example.com")
	asset.Vulnerabilities = []*Vulnerability{
		{Severity: "low", TemplateID: "low-1", Title: "Low issue"},
		{Severity: "critical", TemplateID: "crit-1", Title: "Critical issue"},
		{Severity: "high", TemplateID: "high-1", Title: "High issue"},
	}

	table := FormatFindingsTable(rep)
	if table == "" {
		t.Fatal("expected a non-empty table")
	}
	crit := strings.Index(table, "CRITICAL")
	high := strings.Index(table, "HIGH")
	low := strings.Index(table, "LOW")
	if crit == -1 || high == -1 || low == -1 {
		t.Fatalf("table missing severity labels: %s", table)
	}
	if crit >= high || high >= low {
		t.Errorf("expected CRITICAL < HIGH < LOW order, got positions crit=%d high=%d low=%d", crit, high, low)
	}
	if !strings.Contains(table, "crit-1") || !strings.Contains(table, "Critical issue") {
		t.Errorf("table missing finding details: %s", table)
	}
}

func TestFormatFindingsTableCapsAtMax(t *testing.T) {
	rep := NewReport("example.com", "web")
	asset := rep.GetOrCreateAsset("example.com")
	for i := 0; i < maxFindings+5; i++ {
		asset.Vulnerabilities = append(asset.Vulnerabilities, &Vulnerability{
			Severity: "info", TemplateID: "t", Title: "issue",
		})
	}

	table := FormatFindingsTable(rep)
	if !strings.Contains(table, "and 5 more") {
		t.Errorf("expected truncation row announcing 5 more, got: %s", table)
	}
}
