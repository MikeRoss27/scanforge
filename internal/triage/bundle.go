package triage

import (
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/MikeRoss27/scanforge/internal/finding"
)

// TriageFinding is the deliberately reduced projection of a Finding that is
// sent to the LLM. Raw scanner output is never forwarded: evidence and
// descriptions are truncated, and fields that could carry secrets or
// target-controlled content (full response bodies, payloads) are excluded.
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
	Evidence   string   `json:"evidence,omitempty"`
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

// MaxEvidenceLen and MaxDescriptionLen bound the size of per-finding text
// sent to the model.
const (
	MaxEvidenceLen = 500
)

// BuildBundle projects the authoritative findings into the safe bundle. The
// projection is deterministic and lossy on purpose.
func BuildBundle(target string, findings []finding.Finding, relations []finding.FindingRelation) TriageBundle {
	bundle := TriageBundle{Target: target, Relations: relations}

	limit := MaxBundleFindings
	if len(findings) < limit {
		limit = len(findings)
	}
	for _, f := range findings[:limit] {
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
			Evidence:   truncate(f.Evidence, MaxEvidenceLen),
			MatchedAt:  f.MatchedAt,
		})
	}
	bundle.Truncated = len(findings) - limit
	return bundle
}

// MarshalJSON renders the bundle for the prompt.
func (b TriageBundle) MarshalJSON() ([]byte, error) {
	type alias TriageBundle
	return json.Marshal(alias(b))
}

// truncate cuts value to at most max bytes without splitting a UTF-8 rune.
func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	cut := max - len("…")
	if cut < 0 {
		cut = 0
	}
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return strings.TrimSpace(value[:cut]) + "…"
}
