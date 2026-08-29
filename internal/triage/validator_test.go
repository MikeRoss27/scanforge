package triage

import (
	"testing"

	"github.com/MikeRoss27/scanforge/internal/finding"
)

func TestValidateInsightsRejectsUnknownFacts(t *testing.T) {
	f := mkFinding("nuclei", "t-1", "a.com", "https://a.com/x", []string{"CVE-2026-0001"})
	f.Evidence = "HTTP/1.1 200 OK"
	findings := []finding.Finding{f}

	cases := []struct {
		name     string
		insight  TriageInsight
		rejected bool
	}{
		{
			name: "valid",
			insight: TriageInsight{
				Kind: InsightPriority, FindingIDs: []finding.ID{f.ID},
				Summary: "ok", Priority: finding.PrioHigh, Confidence: 0.9,
				CVEs: []string{"CVE-2026-0001"}, EvidenceRefs: []string{"HTTP/1.1 200"},
				Source: SourceLLM,
			},
			rejected: false,
		},
		{
			name: "unknown finding id",
			insight: TriageInsight{
				Kind: InsightPriority, FindingIDs: []finding.ID{"F-0000000000000000"},
				Summary: "bad", Priority: finding.PrioHigh, Confidence: 0.9, Source: SourceLLM,
			},
			rejected: true,
		},
		{
			name: "unknown cve",
			insight: TriageInsight{
				Kind: InsightPriority, FindingIDs: []finding.ID{f.ID},
				Summary: "bad", Priority: finding.PrioHigh, Confidence: 0.9,
				CVEs: []string{"CVE-2026-99999"}, Source: SourceLLM,
			},
			rejected: true,
		},
		{
			name: "unknown evidence ref",
			insight: TriageInsight{
				Kind: InsightPriority, FindingIDs: []finding.ID{f.ID},
				Summary: "bad", Priority: finding.PrioHigh, Confidence: 0.9,
				EvidenceRefs: []string{"totally-made-up-string"}, Source: SourceLLM,
			},
			rejected: true,
		},
		{
			name: "no finding ids",
			insight: TriageInsight{
				Kind: InsightPriority, Summary: "bad", Priority: finding.PrioHigh,
				Confidence: 0.9, Source: SourceLLM,
			},
			rejected: true,
		},
		{
			name: "unknown kind",
			insight: TriageInsight{
				Kind: "invented_kind", FindingIDs: []finding.ID{f.ID},
				Summary: "bad", Priority: finding.PrioHigh, Confidence: 0.9, Source: SourceLLM,
			},
			rejected: true,
		},
		{
			name: "confidence out of range",
			insight: TriageInsight{
				Kind: InsightPriority, FindingIDs: []finding.ID{f.ID},
				Summary: "bad", Priority: finding.PrioHigh, Confidence: 1.5, Source: SourceLLM,
			},
			rejected: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			valid, rejected := ValidateInsights([]TriageInsight{tc.insight}, findings)
			if tc.rejected && rejected != 1 {
				t.Errorf("expected 1 rejection, got %d (valid=%+v)", rejected, valid)
			}
			if !tc.rejected && rejected != 0 {
				t.Errorf("expected 0 rejections, got %d", rejected)
			}
		})
	}
}

func TestValidateInsightsEvidenceRefMatchesURL(t *testing.T) {
	f := mkFinding("nuclei", "t-1", "a.com", "https://a.com/x", nil)
	insight := TriageInsight{
		Kind: InsightObservation, FindingIDs: []finding.ID{f.ID},
		Summary: "ok", Priority: finding.PrioLow, Confidence: 0.5,
		EvidenceRefs: []string{"https://a.com/x"}, Source: SourceLLM,
	}
	valid, rejected := ValidateInsights([]TriageInsight{insight}, []finding.Finding{f})
	if rejected != 0 || len(valid) != 1 {
		t.Errorf("URL evidence ref should be valid: rejected=%d valid=%d", rejected, len(valid))
	}
}
