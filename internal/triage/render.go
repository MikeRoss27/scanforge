package triage

import (
	"fmt"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/finding"
)

// RenderMarkdown renders the triage result as a human-readable report.
func RenderMarkdown(result *Result) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# Triage — %s\n\n", result.Manifest.Model)
	fmt.Fprintf(&b, "Input digest: `%s` · prompt `%s` · %s\n\n",
		result.Manifest.InputDigest, result.Manifest.PromptVersion, result.Manifest.CreatedAt)
	if result.Manifest.CacheHit {
		b.WriteString("> Cached result (input unchanged).\n\n")
	}
	if result.Manifest.LLMError != "" {
		fmt.Fprintf(&b, "> LLM analysis failed: %s\n\n", result.Manifest.LLMError)
	}
	if result.Manifest.Rejected > 0 {
		fmt.Fprintf(&b, "> %d LLM insight(s) rejected by validation.\n\n", result.Manifest.Rejected)
	}

	fmt.Fprintf(&b, "## Insights (%d)\n\n", len(result.Insights))
	for _, insight := range result.Insights {
		source := "deterministic"
		if insight.Source == SourceLLM {
			source = "llm"
		}
		fmt.Fprintf(&b, "### %s · %s · %s (%.2f) · %s\n\n",
			insight.ID, insight.Kind, insight.Priority, insight.Confidence, source)
		b.WriteString(insight.Summary)
		b.WriteString("\n\n")
		if len(insight.FindingIDs) > 0 {
			fmt.Fprintf(&b, "- Findings: %s\n", strings.Join(ids(insight.FindingIDs), ", "))
		}
		if len(insight.CVEs) > 0 {
			fmt.Fprintf(&b, "- CVEs: %s\n", strings.Join(insight.CVEs, ", "))
		}
		if len(insight.EvidenceRefs) > 0 {
			fmt.Fprintf(&b, "- Evidence: %s\n", strings.Join(insight.EvidenceRefs, ", "))
		}
		if len(insight.Uncertainty) > 0 {
			fmt.Fprintf(&b, "- Uncertainty: %s\n", strings.Join(insight.Uncertainty, "; "))
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## Relations (%d)\n\n", len(result.Relations))
	for _, rel := range result.Relations {
		fmt.Fprintf(&b, "- `%s` → `%s` · %s · %.2f · %s\n",
			rel.From, rel.To, rel.Type, rel.Confidence, rel.Source)
	}
	return strings.TrimRight(b.String(), "\n")
}

func ids(values []finding.ID) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = string(v)
	}
	return out
}
