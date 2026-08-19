package triage

import (
	"strings"

	"github.com/MikeRoss27/scanforge/internal/finding"
)

// ValidateInsights checks every LLM-produced insight against the
// authoritative facts and drops the ones that reference anything unknown:
// finding IDs, CVEs and evidence strings must all exist in the findings.
// This is the boundary that keeps the model from injecting new "truths".
// It returns the valid insights and the number of rejected ones.
func ValidateInsights(insights []TriageInsight, findings []finding.Finding) (valid []TriageInsight, rejected int) {
	known := indexFacts(findings)
	for _, insight := range insights {
		if validInsight(insight, known) {
			valid = append(valid, insight)
		} else {
			rejected++
		}
	}
	return valid, rejected
}

// knownFacts indexes every fact the model is allowed to reference.
type knownFacts struct {
	findings map[finding.ID]finding.Finding
	cves     map[string]struct{}
	evidence []string // concatenated evidence/url/matched_at/title per finding
}

func indexFacts(findings []finding.Finding) knownFacts {
	k := knownFacts{
		findings: make(map[finding.ID]finding.Finding, len(findings)),
		cves:     make(map[string]struct{}),
	}
	for _, f := range findings {
		k.findings[f.ID] = f
		for _, cve := range f.CVEs {
			k.cves[strings.ToLower(strings.TrimSpace(cve))] = struct{}{}
		}
		k.evidence = append(k.evidence,
			f.Evidence, f.URL, f.MatchedAt, f.Title, f.Asset)
	}
	return k
}

func validInsight(insight TriageInsight, known knownFacts) bool {
	switch insight.Kind {
	case InsightSummary, InsightPriority, InsightExploitability, InsightObservation:
	default:
		return false
	}
	if insight.Confidence < 0 || insight.Confidence > 1 {
		return false
	}
	if len(insight.FindingIDs) == 0 {
		return false
	}
	for _, id := range insight.FindingIDs {
		if _, ok := known.findings[id]; !ok {
			return false
		}
	}
	for _, cve := range insight.CVEs {
		if _, ok := known.cves[strings.ToLower(strings.TrimSpace(cve))]; !ok {
			return false
		}
	}
	for _, ref := range insight.EvidenceRefs {
		if !containsEvidence(known.evidence, ref) {
			return false
		}
	}
	return true
}

// containsEvidence reports whether the reference appears in any finding's
// evidence, URL, matched location, title or asset.
func containsEvidence(haystack []string, ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return false
	}
	for _, value := range haystack {
		if value != "" && strings.Contains(value, ref) {
			return true
		}
	}
	return false
}
