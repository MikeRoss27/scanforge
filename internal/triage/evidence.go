package triage

import (
	"fmt"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/finding"
	"github.com/MikeRoss27/scanforge/internal/report"
)

// Triage consumes the evidence layer (finding.Status / finding.Confidence) as
// read-only input. It never writes a status: only the module that verified a
// finding can set one, so an insight can be more cautious than the findings
// it covers but never more assertive.

// statusSummary renders a "N validated, M potential, ..." breakdown, or ""
// when no finding carries a status (reports from older runs).
func statusSummary(findings []finding.Finding) string {
	counts := map[string]int{}
	for _, f := range findings {
		if f.Status != "" {
			counts[f.Status]++
		}
	}
	if len(counts) == 0 {
		return ""
	}
	var parts []string
	for _, s := range []string{report.StatusValidated, report.StatusVersionMatch, report.StatusInconclusive, report.StatusPotential} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	return strings.Join(parts, ", ")
}

// confidenceCap bounds an LLM insight's self-reported confidence by the
// weakest evidence confidence among the findings it covers.
func confidenceCap(c string) float64 {
	switch c {
	case report.ConfidenceLow:
		return 0.4
	case report.ConfidenceMedium:
		return 0.7
	default:
		return 1.0
	}
}

// applyEvidence annotates insights with what the covered findings do NOT
// establish. For every insight with at least one covered finding:
//   - when no covered finding is validated (and at least one carries a
//     status), an "unverified" uncertainty entry is added;
//   - LLM insights get their confidence capped by the weakest covered
//     finding confidence (deterministic insights keep their rule-based value).
//
// Statuses and finding data are never modified.
func applyEvidence(insights []TriageInsight, findings []finding.Finding) []TriageInsight {
	byID := make(map[finding.ID]finding.Finding, len(findings))
	for _, f := range findings {
		byID[f.ID] = f
	}
	out := make([]TriageInsight, len(insights))
	copy(out, insights)
	for i := range out {
		in := &out[i]
		var covered, withStatus, validated int
		weakest := ""
		for _, id := range in.FindingIDs {
			f, ok := byID[id]
			if !ok {
				continue
			}
			covered++
			if f.Status != "" {
				withStatus++
			}
			if f.Status == report.StatusValidated {
				validated++
			}
			weakest = weaker(weakest, f.Confidence)
		}
		if covered == 0 || withStatus == 0 {
			continue
		}
		if validated == 0 {
			note := fmt.Sprintf("none of the %d covered finding(s) is validated; statuses are module-set and unchanged by triage", covered)
			in.Uncertainty = append(append([]string(nil), in.Uncertainty...), note)
		}
		if in.Source == SourceLLM && weakest != "" {
			if limit := confidenceCap(weakest); in.Confidence > limit {
				in.Confidence = limit
			}
		}
	}
	return out
}

// weaker returns the lower of two confidence labels ("" means unknown and
// yields to any known label).
func weaker(a, b string) string {
	rank := func(c string) int {
		switch c {
		case report.ConfidenceLow:
			return 1
		case report.ConfidenceMedium:
			return 2
		case report.ConfidenceHigh:
			return 3
		}
		return 0
	}
	switch {
	case rank(b) == 0:
		return a
	case rank(a) == 0, rank(b) < rank(a):
		return b
	}
	return a
}
