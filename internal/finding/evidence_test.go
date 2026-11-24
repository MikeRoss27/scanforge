package finding

import (
	"testing"

	"github.com/MikeRoss27/scanforge/internal/report"
)

func evidenceReportFixture() *report.Report {
	rep := report.NewReport("example.com", "web")
	asset := rep.GetOrCreateAsset("app.example.com")
	asset.Vulnerabilities = append(asset.Vulnerabilities, &report.Vulnerability{
		Source: "nuclei", TemplateID: "t1", Title: "T1", Severity: "medium", MatchedAt: "https://app.example.com/x",
		Provenance: &report.Provenance{Module: "nuclei", Tool: "nuclei", ToolVersion: "v3"},
		Status:     report.StatusPotential, Confidence: report.ConfidenceMedium,
		EvidenceItems: []report.Evidence{{Kind: report.EvidenceTemplateMatch, Summary: "s", VerifiedBy: "template matcher fired"}},
	})
	asset.Vulnerabilities = append(asset.Vulnerabilities, &report.Vulnerability{
		Source: "nuclei", TemplateID: "legacy", Title: "Legacy", Severity: "low", MatchedAt: "https://app.example.com/y",
	})
	rep.JSVerified = []report.VerifiedFinding{
		{URL: "https://app.example.com/app.js", Page: "https://app.example.com/", Kind: "dom-sink", Pattern: "innerHTML", Severity: "medium", Verdict: "executed", Evidence: "alert fired"},
		{URL: "https://app.example.com/app.js", Page: "https://app.example.com/", Kind: "dom-sink", Pattern: "eval", Severity: "medium", Verdict: "sink-reached"},
	}
	return rep
}

func TestFromReportCarriesEvidenceLayer(t *testing.T) {
	findings := FromReport(evidenceReportFixture())
	if len(findings) != 4 {
		t.Fatalf("findings = %d, want 4", len(findings))
	}
	tests := []struct {
		templateID string
		status     string
		confidence string
		module     string
	}{
		{"t1", report.StatusPotential, report.ConfidenceMedium, "nuclei"},
		{"legacy", "", "", ""},
		{"innerHTML", report.StatusValidated, report.ConfidenceHigh, "jsverify"},
		{"eval", report.StatusInconclusive, report.ConfidenceMedium, "jsverify"},
	}
	for _, tt := range tests {
		t.Run(tt.templateID, func(t *testing.T) {
			var got *Finding
			for i := range findings {
				if findings[i].TemplateID == tt.templateID {
					got = &findings[i]
				}
			}
			if got == nil {
				t.Fatal("finding missing")
			}
			if got.Status != tt.status || got.Confidence != tt.confidence {
				t.Errorf("status/confidence = %q/%q, want %q/%q", got.Status, got.Confidence, tt.status, tt.confidence)
			}
			if tt.module == "" {
				if got.Provenance != nil || len(got.EvidenceItems) != 0 {
					t.Errorf("legacy finding grew evidence: %+v", got)
				}
				return
			}
			if got.Provenance == nil || got.Provenance.Module != tt.module {
				t.Errorf("provenance = %+v", got.Provenance)
			}
			if len(got.EvidenceItems) == 0 || got.EvidenceItems[0].VerifiedBy == "" {
				t.Errorf("evidence items = %+v", got.EvidenceItems)
			}
		})
	}
}

// TestFingerprintIgnoresEvidenceLayer: finding IDs must not change when the
// evidence layer is present, or caches, diffs and triage would all churn.
func TestFingerprintIgnoresEvidenceLayer(t *testing.T) {
	base := Finding{Source: "nuclei", TemplateID: "t", Asset: "a", MatchedAt: "https://a/x", Evidence: "e"}
	withEvidence := base
	withEvidence.Status = report.StatusValidated
	withEvidence.Confidence = report.ConfidenceHigh
	withEvidence.Provenance = &report.Provenance{Module: "nuclei"}
	withEvidence.EvidenceItems = []report.Evidence{{Kind: "k"}}
	if base.Fingerprint() != withEvidence.Fingerprint() {
		t.Error("fingerprint depends on the evidence layer")
	}
}
