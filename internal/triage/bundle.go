package triage

import (
	"encoding/json"

	"github.com/MikeRoss27/scanforge/internal/finding"
)

// TriageFinding is the deliberately reduced projection of a Finding that is
// sent to the LLM. Raw scanner output is never forwarded: evidence and
// descriptions are truncated, and fields that could carry secrets or
// target-controlled content (full response bodies, payloads) are excluded.
// Evidence is intentionally omitted to prevent credential leakage; a static
// placeholder is used instead.
type TriageFinding struct {
	ID         string   `json:"id"`
	Asset      string   `json:"asset"`
	URL        string   `json:"url,omitempty"`
	Severity   string   `json:"severity"`
	Source     string   `json:"source"`
	TemplateID string   `json:"template_id,omitempty"`
	Title      string   `json:"title"`
	Tags       []string `json:"tags,omitempty"`
	CVEs       []string `json:"cves,omitempty"`
	CVSS       float64  `json:"cvss,omitempty"`
	EPSS       float64  `json:"epss,omitempty"`
	KEV        bool     `json:"kev,omitempty"`
	MatchedAt  string   `json:"matched_at"`
}

// TriageBundle is the complete, safe context handed to the analyzer. It
// contains only projections of authoritative data.
type TriageBundle struct {
	Target    string                    `json:"target"`
	Findings  []TriageFinding           `json:"findings"`
	Relations []finding.FindingRelation `json:"relations"`
	// Truncated reports how many findings were left out of the bundle
	// because the run exceeded MaxBundleFindings.
	Truncated int `json:"truncated,omitempty"`
}

// BuildBundle projects the authoritative findings into the safe bundle. The
// projection is deterministic and lossy on purpose.
func BuildBundle(target string, findings []finding.Finding, relations []finding.FindingRelation) TriageBundle {
	bundle := TriageBundle{Target: target}

	limit := MaxBundleFindings
	if len(findings) < limit {
		limit = len(findings)
	}
	included := make(map[finding.ID]struct{}, limit)
	for _, f := range findings[:limit] {
		included[f.ID] = struct{}{}
		bundle.Findings = append(bundle.Findings, TriageFinding{
			ID:         string(f.ID),
			Asset:      f.Asset,
			URL:        f.URL,
			Severity:   string(f.Severity),
			Source:     f.Source,
			TemplateID: f.TemplateID,
			Title:      f.Title,
			Tags:       f.Tags,
			CVEs:       f.CVEs,
			CVSS:       f.CVSS,
			EPSS:       f.EPSS,
			KEV:        f.KEV,
			MatchedAt:  f.MatchedAt,
		})
	}

	// Filter relations to only include those where both endpoints are in the bundle.
	for _, rel := range relations {
		if _, ok1 := included[rel.From]; ok1 {
			if _, ok2 := included[rel.To]; ok2 {
				bundle.Relations = append(bundle.Relations, rel)
			}
		}
	}

	bundle.Truncated = len(findings) - limit
	return bundle
}

// MarshalJSON renders the bundle for the prompt.
func (b TriageBundle) MarshalJSON() ([]byte, error) {
	type alias TriageBundle
	return json.Marshal(alias(b))
}
