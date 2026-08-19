// Package triage derives interpretation from ScanForge's authoritative
// findings: deterministic deduplication and grouping, plus optional LLM
// analysis whose output is validated against the facts before being stored.
// Findings are facts owned by ScanForge; insights are derived, auditable and
// never authoritative.
package triage

import (
	"time"

	"github.com/MikeRoss27/scanforge/internal/finding"
)

// SchemaVersion of the triage output files (manifest.json, insights.json).
const SchemaVersion = 1

// PromptVersion identifies the LLM prompt and output schema. Bumping it
// invalidates cached insights.
const PromptVersion = "triage-v1"

// MaxBundleFindings caps how many findings are sent to the LLM. Deterministic
// insights always cover every finding; the bundle only feeds the LLM.
const MaxBundleFindings = 150

// InsightKind classifies a triage insight.
type InsightKind string

const (
	// InsightSummary is a global assessment of the findings.
	InsightSummary InsightKind = "summary"
	// InsightDuplicate flags a group of findings that are likely the same issue.
	InsightDuplicate InsightKind = "duplicate_group"
	// InsightPriority says which findings to address first and why.
	InsightPriority InsightKind = "priority"
	// InsightExploitability says whether a finding appears exploitable.
	InsightExploitability InsightKind = "exploitability"
	// InsightObservation is any other useful interpretation.
	InsightObservation InsightKind = "observation"
)

// InsightSource says where an insight came from. Deterministic insights are
// computed from rules; LLM insights are model interpretations.
type InsightSource string

const (
	SourceDeterministic InsightSource = "deterministic"
	SourceLLM           InsightSource = "llm"
)

// TriageInsight is a derived interpretation of one or more findings. It never
// creates facts: every referenced finding ID, CVE or evidence string must
// exist in the authoritative findings.
type TriageInsight struct {
	ID           finding.ID       `json:"id"`
	Kind         InsightKind      `json:"kind"`
	FindingIDs   []finding.ID     `json:"finding_ids"`
	Summary      string           `json:"summary"`
	Priority     finding.Priority `json:"priority"`
	Confidence   float64          `json:"confidence"`
	CVEs         []string         `json:"cves,omitempty"`
	EvidenceRefs []string         `json:"evidence_refs,omitempty"`
	Uncertainty  []string         `json:"uncertainty,omitempty"`
	Source       InsightSource    `json:"source"`
}

// TriageManifest records the provenance of a triage run so results are
// reproducible and auditable: which model, which prompt version, which input.
type TriageManifest struct {
	SchemaVersion int     `json:"schema_version"`
	PromptVersion string  `json:"prompt_version"`
	Model         string  `json:"model"`
	Provider      string  `json:"provider"`
	InputDigest   string  `json:"input_digest"`
	CreatedAt     string  `json:"created_at"`
	Temperature   float64 `json:"temperature"`
	CacheHit      bool    `json:"cache_hit,omitempty"`
	Rejected      int     `json:"rejected_insights,omitempty"`
	LLMError      string  `json:"llm_error,omitempty"`
}

// Stats summarizes one triage run for the CLI output.
type Stats struct {
	Findings    int
	Relations   int
	Insights    int
	LLMInsights int
	Rejected    int
	CacheHit    bool
	LLMError    string
}

// Result is the outcome of one triage run.
type Result struct {
	Manifest  TriageManifest
	Insights  []TriageInsight
	Relations []finding.FindingRelation
	Stats     Stats
	// Dir is the directory the outputs were written to (OutDir).
	Dir string
}

// ModelConfig describes the LLM backend used by the analyzer. A nil model
// means deterministic-only triage.
type ModelConfig struct {
	BaseURL     string
	Model       string
	APIKey      string
	Timeout     time.Duration
	Temperature float64
}

// Input is everything the engine needs to triage one run.
type Input struct {
	Target    string
	Findings  []finding.Finding
	Relations []finding.FindingRelation
	Model     *ModelConfig
	Force     bool
	// OutDir receives triage/manifest.json, insights.json, relations.json and
	// report.md. It is also the cache location.
	OutDir string
}

// Output file names inside OutDir.
const (
	FileManifest  = "manifest.json"
	FileInsights  = "insights.json"
	FileRelations = "relations.json"
	FileReportMD  = "report.md"
)
