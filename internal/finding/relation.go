package finding

import (
	"sort"
	"strings"
)

// RelationType classifies the relationship between two findings.
type RelationType string

const (
	// RelDuplicate marks two findings that are the same issue (same source,
	// same template, same asset). Deterministic, confidence 1.0.
	RelDuplicate RelationType = "duplicate"
	// RelSameCVE marks findings sharing at least one CVE identifier.
	RelSameCVE RelationType = "same_cve"
	// RelSameEndpoint marks findings on the exact same URL.
	RelSameEndpoint RelationType = "same_endpoint"
	// RelSameAsset marks findings on the same host.
	RelSameAsset RelationType = "same_asset"
)

// RelationSource says where a relation came from. Deterministic relations are
// authoritative; LLM relations are derived and never override them.
type RelationSource string

const (
	RelSourceDeterministic RelationSource = "deterministic"
	RelSourceLLM           RelationSource = "llm"
)

// FindingRelation links two findings. The confidence expresses how strongly
// the relation is believed: 1.0 for exact duplicates, down to 0.8 for the
// same-asset heuristic.
type FindingRelation struct {
	From       ID             `json:"from"`
	To         ID             `json:"to"`
	Type       RelationType   `json:"type"`
	Confidence float64        `json:"confidence"`
	Source     RelationSource `json:"source"`
}

// BuildRelations computes the deterministic (L0/L1) relations between every
// pair of findings. The strongest applicable rule wins per pair:
//
//	duplicate (same source+template+asset)     → 1.00
//	shared CVE                                 → 0.99
//	same URL endpoint                          → 0.95
//	same asset                                 → 0.80
//
// The result is sorted for determinism. This is the L0/L1 layer: semantic
// (L2) relations produced later by an LLM can add to it but never override it.
func BuildRelations(findings []Finding) []FindingRelation {
	var relations []FindingRelation
	for i := 0; i < len(findings); i++ {
		for j := i + 1; j < len(findings); j++ {
			if rel, ok := strongestRelation(findings[i], findings[j]); ok {
				// Canonicalize direction so the graph is independent of the
				// input order: From always sorts before To.
				if rel.From > rel.To {
					rel.From, rel.To = rel.To, rel.From
				}
				relations = append(relations, rel)
			}
		}
	}
	sort.Slice(relations, func(a, b int) bool {
		if relations[a].From != relations[b].From {
			return relations[a].From < relations[b].From
		}
		if relations[a].To != relations[b].To {
			return relations[a].To < relations[b].To
		}
		return relations[a].Type < relations[b].Type
	})
	return relations
}

// strongestRelation returns the strongest deterministic relation between two
// findings, or ok=false when none applies.
func strongestRelation(a, b Finding) (FindingRelation, bool) {
	if a.Source == b.Source && a.TemplateID != "" && a.TemplateID == b.TemplateID && a.Asset == b.Asset {
		return FindingRelation{From: a.ID, To: b.ID, Type: RelDuplicate, Confidence: 1.0, Source: RelSourceDeterministic}, true
	}
	if shareAny(a.CVEs, b.CVEs) {
		return FindingRelation{From: a.ID, To: b.ID, Type: RelSameCVE, Confidence: 0.99, Source: RelSourceDeterministic}, true
	}
	if a.URL != "" && a.URL == b.URL {
		return FindingRelation{From: a.ID, To: b.ID, Type: RelSameEndpoint, Confidence: 0.95, Source: RelSourceDeterministic}, true
	}
	if a.Asset != "" && a.Asset == b.Asset {
		return FindingRelation{From: a.ID, To: b.ID, Type: RelSameAsset, Confidence: 0.80, Source: RelSourceDeterministic}, true
	}
	return FindingRelation{}, false
}

func shareAny(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, value := range a {
		set[strings.ToLower(strings.TrimSpace(value))] = struct{}{}
	}
	for _, value := range b {
		if _, ok := set[strings.ToLower(strings.TrimSpace(value))]; ok {
			return true
		}
	}
	return false
}
