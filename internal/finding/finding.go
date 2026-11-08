// Package finding defines the canonical, authoritative representation of a
// security finding projected from the consolidated report, plus the
// deterministic relations between findings (duplicates, shared CVE, shared
// endpoint, ...). Findings are ScanForge-owned facts: the AI triage layer may
// interpret them but never create or modify them.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// ID is the stable, deterministic identifier of a finding. It is derived from
// the finding's identity fields, so the same finding re-discovered in a later
// run gets the same ID (which powers caching, diffing and validation).
type ID string

// Severity is the normalized severity of a finding.
type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// NormalizeSeverity maps any scanner severity label onto the canonical set.
// Unknown labels fall back to info so downstream layers always see one of the
// five canonical values.
func NormalizeSeverity(value string) Severity {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return SevCritical
	case "high":
		return SevHigh
	case "medium", "moderate":
		return SevMedium
	case "low":
		return SevLow
	case "info", "informational", "none":
		return SevInfo
	default:
		return SevInfo
	}
}

// Finding is one security issue discovered during a run. It is a flat
// projection of report.Vulnerability (and similar report entries) enriched
// with the owning asset and a deterministic ID.
type Finding struct {
	ID          ID       `json:"id"`
	Kind        string   `json:"kind"`
	Asset       string   `json:"asset"`
	URL         string   `json:"url,omitempty"`
	Severity    Severity `json:"severity"`
	Source      string   `json:"source"`
	TemplateID  string   `json:"template_id,omitempty"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	CVEs        []string `json:"cves,omitempty"`
	CWEs        []string `json:"cwes,omitempty"`
	References  []string `json:"references,omitempty"`
	CVSS        float64  `json:"cvss,omitempty"`
	EPSS        float64  `json:"epss,omitempty"`
	KEV         bool     `json:"kev,omitempty"`
	MatchedAt   string   `json:"matched_at"`
}

// Fingerprint computes the deterministic ID from the identity fields. The
// evidence hash is part of the identity so two findings that differ only in
// their evidence remain distinct.
func (f *Finding) Fingerprint() ID {
	identity := strings.Join([]string{
		f.Source, f.TemplateID, f.Asset, f.MatchedAt, f.Evidence,
	}, "|")
	sum := sha256.Sum256([]byte(identity))
	return ID("F-" + hex.EncodeToString(sum[:])[:16])
}

// Priority derives the triage priority from the severity.
func (f *Finding) Priority() Priority {
	return PriorityFromSeverity(f.Severity)
}

// Priority is the triage priority of an insight or finding.
type Priority string

const (
	PrioNone     Priority = "none"
	PrioLow      Priority = "low"
	PrioMedium   Priority = "medium"
	PrioHigh     Priority = "high"
	PrioCritical Priority = "critical"
)

// PriorityFromSeverity maps a severity onto the canonical priority set.
func PriorityFromSeverity(sev Severity) Priority {
	switch sev {
	case SevCritical:
		return PrioCritical
	case SevHigh:
		return PrioHigh
	case SevMedium:
		return PrioMedium
	case SevLow:
		return PrioLow
	default:
		return PrioNone
	}
}

// ParsePriority normalizes a user or model supplied priority label.
func ParsePriority(value string) (Priority, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return PrioCritical, nil
	case "high":
		return PrioHigh, nil
	case "medium":
		return PrioMedium, nil
	case "low":
		return PrioLow, nil
	case "none", "":
		return PrioNone, nil
	default:
		return "", fmt.Errorf("unknown priority %q", value)
	}
}
