package report

import (
	"path/filepath"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/version"
)

// Finding status values. A status says how far a finding has been verified,
// nothing more. It is only ever raised by the module that actually performed
// the verification (see docs/EVIDENCE.md); no consumer (triage, export, MCP)
// may upgrade it.
const (
	// StatusPotential: a tool or pattern reported it, nothing verified it.
	StatusPotential = "potential"
	// StatusVersionMatch: the detected product version falls in an affected
	// range. The vulnerability itself was not exercised.
	StatusVersionMatch = "version-match"
	// StatusValidated: a module reproduced or directly observed the issue.
	StatusValidated = "validated"
	// StatusInconclusive: a verification was attempted and gave an ambiguous
	// or partial result.
	StatusInconclusive = "inconclusive"
)

// Confidence levels (categorical on purpose: no false numeric precision).
const (
	ConfidenceLow    = "low"
	ConfidenceMedium = "medium"
	ConfidenceHigh   = "high"
)

// Evidence kinds.
const (
	EvidenceTemplateMatch = "template-match"
	EvidenceVersionMatch  = "version-match"
	EvidenceStaticMatch   = "static-match"
	EvidenceReplay        = "replay"
	EvidenceObservation   = "http-observation"
	EvidenceAuth          = "authentication"
)

// Provenance says which module (and which underlying tool, at which version
// when known) produced a finding.
type Provenance struct {
	Module      string `json:"module"`
	Tool        string `json:"tool,omitempty"`
	ToolVersion string `json:"tool_version,omitempty"`
}

// Evidence is one piece of proof attached to a finding. Excerpts are kept
// verbatim: values leaked by the target (secrets, tokens) are bounty proof
// and are never masked here. Only the operator's own credentials are
// scrubbed, and that happens at the log/serving layer, not in the report.
type Evidence struct {
	Kind    string `json:"kind"`
	Summary string `json:"summary"`
	// Artifact is the run-relative path of the raw output the evidence comes
	// from (e.g. 06_vulns/nuclei.jsonl).
	Artifact string `json:"artifact,omitempty"`
	Excerpt  string `json:"excerpt,omitempty"`
	// VerifiedBy states what was ACTUALLY verified, in plain words. For a
	// potential finding it says so explicitly.
	VerifiedBy string `json:"verified_by"`
}

// nativeModules are implemented inside ScanForge (no external binary).
var nativeModules = map[string]bool{
	"jssecrets": true, "jsverify": true, "techcve": true, "httpcheck": true,
	"wpcve": true, "wpusers": true, "wpexposure": true, "wpxmlrpc": true, "wpbrute": true,
}

// ProvenanceFor builds the provenance of a module's finding.
func (r *Report) ProvenanceFor(module string) *Provenance {
	if nativeModules[module] {
		return &Provenance{Module: module, Tool: "scanforge", ToolVersion: version.Version}
	}
	return &Provenance{Module: module, Tool: module, ToolVersion: r.toolVersions[module]}
}

// artifactRef returns path relative to the run directory when known, with
// forward slashes, so report.json does not leak absolute local paths.
func (r *Report) artifactRef(path string) string {
	if path == "" {
		return ""
	}
	if r.runDir != "" {
		if rel, err := filepath.Rel(r.runDir, path); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(path)
}

// annotate sets the provenance, status, confidence and first evidence entry
// of a vulnerability in one place so every parser applies the same shape.
func (r *Report) annotate(v *Vulnerability, module, status, confidence string, ev Evidence, artifactPath string) {
	v.Provenance = r.ProvenanceFor(module)
	v.Status = status
	v.Confidence = confidence
	ev.Artifact = r.artifactRef(artifactPath)
	v.EvidenceItems = append(v.EvidenceItems, ev)
}

// normalizeConfidence maps a module-supplied confidence label onto the
// canonical set, falling back when the label is unknown.
func normalizeConfidence(value, fallback string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case ConfidenceLow:
		return ConfidenceLow
	case ConfidenceMedium:
		return ConfidenceMedium
	case ConfidenceHigh:
		return ConfidenceHigh
	default:
		return fallback
	}
}

// ValidStatus reports whether s is one of the four canonical statuses.
func ValidStatus(s string) bool {
	switch s {
	case StatusPotential, StatusVersionMatch, StatusValidated, StatusInconclusive:
		return true
	}
	return false
}

// applyReplayVerdicts links jsverify replay verdicts back to the jssecrets
// findings they replayed (same script URL and pattern). Only an "executed"
// verdict validates a finding; "sink-reached" is recorded as inconclusive.
// Findings without a matching verdict keep their status: nothing is inferred.
func (r *Report) applyReplayVerdicts() {
	for _, v := range r.JSVerified {
		status, confidence, ev, ok := r.VerifiedEvidence(v)
		if !ok {
			continue
		}
		asset, found := r.Assets[normalizeAssetName(v.URL)]
		if !found {
			continue
		}
		for _, vuln := range asset.Vulnerabilities {
			if vuln.Source != "jssecrets" || vuln.MatchedAt != v.URL || vuln.TemplateID != v.Pattern {
				continue
			}
			// A validated finding is never downgraded by a weaker replay.
			if vuln.Status != StatusValidated {
				vuln.Status, vuln.Confidence = status, confidence
			}
			vuln.EvidenceItems = append(vuln.EvidenceItems, ev)
		}
	}
}

// VerifiedEvidence derives the status, confidence and evidence entry of one
// jsverify replay verdict. Only "executed" is a validation; "sink-reached"
// (partial observation) is inconclusive; any other verdict yields ok=false
// and must not change a status.
func (r *Report) VerifiedEvidence(v VerifiedFinding) (status, confidence string, ev Evidence, ok bool) {
	ev = Evidence{
		Kind:     EvidenceReplay,
		Summary:  "jsverify replayed a PoC payload on " + v.Page + ": " + v.Verdict,
		Excerpt:  firstNonEmpty(v.Evidence, v.Payload),
		Artifact: r.artifactRef(r.jsVerifyPath),
	}
	switch v.Verdict {
	case "executed":
		ev.VerifiedBy = "payload executed in a headless browser (jsverify verdict executed)"
		return StatusValidated, ConfidenceHigh, ev, true
	case "sink-reached":
		ev.VerifiedBy = "payload reached the sink but execution was not observed (jsverify verdict sink-reached)"
		return StatusInconclusive, ConfidenceMedium, ev, true
	}
	return "", "", ev, false
}
