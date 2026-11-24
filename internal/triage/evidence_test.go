package triage

import (
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/finding"
	"github.com/MikeRoss27/scanforge/internal/report"
)

func evFindings() []finding.Finding {
	return []finding.Finding{
		{ID: "F-1", Asset: "a", Severity: finding.SevHigh, Status: report.StatusPotential, Confidence: report.ConfidenceLow},
		{ID: "F-2", Asset: "a", Severity: finding.SevHigh, Status: report.StatusValidated, Confidence: report.ConfidenceHigh},
		{ID: "F-3", Asset: "b", Severity: finding.SevLow},
	}
}

func TestApplyEvidence(t *testing.T) {
	tests := []struct {
		name         string
		insight      TriageInsight
		wantUncert   bool
		wantConfAtMo float64
	}{
		{"llm insight on unverified finding is capped and flagged",
			TriageInsight{Kind: InsightExploitability, FindingIDs: []finding.ID{"F-1"}, Confidence: 0.95, Source: SourceLLM}, true, 0.4},
		{"llm insight covering a validated finding is not flagged",
			TriageInsight{Kind: InsightPriority, FindingIDs: []finding.ID{"F-2"}, Confidence: 0.9, Source: SourceLLM}, false, 0.9},
		{"mixed coverage is capped by the weakest confidence but not flagged",
			TriageInsight{Kind: InsightPriority, FindingIDs: []finding.ID{"F-1", "F-2"}, Confidence: 0.9, Source: SourceLLM}, false, 0.4},
		{"deterministic insight keeps its confidence",
			TriageInsight{Kind: InsightDuplicate, FindingIDs: []finding.ID{"F-1"}, Confidence: 0.95, Source: SourceDeterministic}, true, 0.95},
		{"legacy finding without status is untouched",
			TriageInsight{Kind: InsightObservation, FindingIDs: []finding.ID{"F-3"}, Confidence: 0.8, Source: SourceLLM}, false, 0.8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := evFindings()
			out := applyEvidence([]TriageInsight{tt.insight}, findings)[0]
			if got := len(out.Uncertainty) > 0; got != tt.wantUncert {
				t.Errorf("uncertainty added = %v (%v), want %v", got, out.Uncertainty, tt.wantUncert)
			}
			if out.Confidence != tt.wantConfAtMo {
				t.Errorf("confidence = %v, want %v", out.Confidence, tt.wantConfAtMo)
			}
			// Triage must never touch the authoritative findings.
			for i, f := range evFindings() {
				if findings[i].Status != f.Status || findings[i].Confidence != f.Confidence {
					t.Errorf("finding %s was modified", f.ID)
				}
			}
		})
	}
}

func TestDeterministicSummaryMentionsStatuses(t *testing.T) {
	insights := deterministicInsights(evFindings(), nil, nil)
	if !strings.Contains(insights[0].Summary, "Verification status: 1 validated, 1 potential.") {
		t.Errorf("summary = %q", insights[0].Summary)
	}
	legacy := deterministicInsights([]finding.Finding{{ID: "F-3", Asset: "b", Severity: finding.SevLow}}, nil, nil)
	if strings.Contains(legacy[0].Summary, "Verification") {
		t.Errorf("legacy summary grew a status clause: %q", legacy[0].Summary)
	}
}

func TestBundleCarriesStatusAndConfidence(t *testing.T) {
	bundle := BuildBundle("t", evFindings(), nil)
	if bundle.Findings[0].Status != report.StatusPotential || bundle.Findings[0].Confidence != report.ConfidenceLow {
		t.Errorf("bundle finding = %+v", bundle.Findings[0])
	}
}
