package triage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/MikeRoss27/scanforge/internal/finding"
)

// Engine runs the triage pipeline: select → group → bundle → analyze →
// validate → reconcile. Deterministic steps always run; the LLM analyzer only
// runs when a model is configured.
type Engine struct {
	// Analyzer is the LLM-backed analyzer. Replaced in tests with a fake.
	Analyzer Analyzer
}

// NewEngine returns an engine whose analyzer is the default LLM analyzer.
func NewEngine() *Engine {
	return &Engine{}
}

// Run executes the triage pipeline for one run and writes the outputs
// (manifest.json, insights.json, relations.json, report.md) into OutDir.
func (e *Engine) Run(ctx context.Context, in Input) (*Result, error) {
	if in.OutDir == "" {
		return nil, fmt.Errorf("triage: OutDir is required")
	}
	if err := os.MkdirAll(in.OutDir, 0755); err != nil {
		return nil, fmt.Errorf("triage: create output dir: %w", err)
	}

	digest := inputDigest(in.Findings, in.Relations)
	temperature := 0.0
	modelName := ""
	if in.Model != nil {
		temperature = in.Model.Temperature
		modelName = in.Model.Model
	}

	// Cache: identical input + model + prompt version → reuse previous run.
	if !in.Force {
		if cached, ok := loadCache(in.OutDir, digest, modelName, temperature); ok {
			cached.Manifest.CacheHit = true
			cached.Stats.CacheHit = true
			return cached, nil
		}
	}

	// Deterministic steps: group related findings and derive insights.
	groups := groupByRelations(in.Relations, in.Findings)
	insights := deterministicInsights(in.Findings, groups, in.Relations)

	stats := Stats{
		Findings:  len(in.Findings),
		Relations: len(in.Relations),
	}

	// Optional LLM step: analyze the safe bundle, then validate the output
	// against the authoritative facts.
	if in.Model != nil {
		analyzer := e.Analyzer
		if analyzer == nil {
			analyzer = NewLLMAnalyzer(in.Model)
		}
		bundle := BuildBundle(in.Target, in.Findings, in.Relations)
		llmInsights, err := analyzer.Analyze(ctx, bundle)
		if err != nil {
			stats.LLMError = err.Error()
		} else {
			valid, rejected := ValidateInsights(llmInsights, in.Findings)
			stats.LLMInsights = len(valid)
			stats.Rejected = rejected
			insights = append(insights, valid...)
		}
	}

	// Reconcile: order insights by priority, then assign stable IDs.
	insights = reconcileInsights(insights)
	stats.Insights = len(insights)

	manifest := TriageManifest{
		SchemaVersion: SchemaVersion,
		PromptVersion: PromptVersion,
		Model:         modelName,
		Provider:      providerName(in.Model),
		InputDigest:   digest,
		CreatedAt:     time.Now().Format(time.RFC3339),
		Temperature:   temperature,
		Rejected:      stats.Rejected,
		LLMError:      stats.LLMError,
	}

	result := &Result{
		Manifest:  manifest,
		Insights:  insights,
		Relations: in.Relations,
		Stats:     stats,
		Dir:       in.OutDir,
	}
	if err := writeOutputs(in.OutDir, result); err != nil {
		return nil, err
	}
	return result, nil
}

// providerName reports the backend label for the manifest.
func providerName(model *ModelConfig) string {
	if model == nil {
		return "deterministic"
	}
	return "openai-compatible"
}

// inputDigest hashes the authoritative input (findings + relations) so the
// cache can detect that nothing changed.
func inputDigest(findings []finding.Finding, relations []finding.FindingRelation) string {
	payload, err := json.Marshal(struct {
		Findings  []finding.Finding         `json:"findings"`
		Relations []finding.FindingRelation `json:"relations"`
	}{findings, relations})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// groupByRelations partitions findings into connected components of the
// relation graph (union-find). Only groups of two or more are returned.
func groupByRelations(relations []finding.FindingRelation, findings []finding.Finding) [][]finding.ID {
	parent := make(map[finding.ID]finding.ID)
	var find func(id finding.ID) finding.ID
	find = func(id finding.ID) finding.ID {
		if parent[id] == "" || parent[id] == id {
			return id
		}
		parent[id] = find(parent[id])
		return parent[id]
	}
	union := func(a, b finding.ID) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[rb] = ra
		}
	}
	for _, rel := range relations {
		union(rel.From, rel.To)
	}

	byRoot := make(map[finding.ID][]finding.ID)
	for _, f := range findings {
		root := find(f.ID)
		byRoot[root] = append(byRoot[root], f.ID)
	}

	var groups [][]finding.ID
	for _, ids := range byRoot {
		if len(ids) < 2 {
			continue
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		groups = append(groups, ids)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i][0] < groups[j][0] })
	return groups
}

// deterministicInsights derives rule-based insights: a global summary and one
// duplicate_group insight per relation group.
func deterministicInsights(findings []finding.Finding, groups [][]finding.ID, relations []finding.FindingRelation) []TriageInsight {
	byID := make(map[finding.ID]finding.Finding, len(findings))
	severityCounts := map[finding.Severity]int{}
	for _, f := range findings {
		byID[f.ID] = f
		severityCounts[f.Severity]++
	}

	insights := []TriageInsight{{
		Kind: InsightSummary,
		Summary: fmt.Sprintf("%d findings across %d assets: %d critical, %d high, %d medium, %d low, %d info.",
			len(findings), countAssets(findings),
			severityCounts[finding.SevCritical], severityCounts[finding.SevHigh],
			severityCounts[finding.SevMedium], severityCounts[finding.SevLow],
			severityCounts[finding.SevInfo]),
		Priority:   maxPriority(findings),
		Confidence: 1.0,
		Source:     SourceDeterministic,
	}}

	for _, ids := range groups {
		priority := finding.PrioNone
		for _, id := range ids {
			if f, ok := byID[id]; ok {
				if p := f.Priority(); priorityRank(p) > priorityRank(priority) {
					priority = p
				}
			}
		}
		insights = append(insights, TriageInsight{
			Kind:       InsightDuplicate,
			FindingIDs: ids,
			Summary:    fmt.Sprintf("%d findings are likely the same issue (deterministic relation).", len(ids)),
			Priority:   priority,
			Confidence: groupConfidence(ids, relations),
			Source:     SourceDeterministic,
		})
	}
	return insights
}

// groupConfidence returns the strongest relation confidence inside a group.
func groupConfidence(ids []finding.ID, relations []finding.FindingRelation) float64 {
	members := make(map[finding.ID]struct{}, len(ids))
	for _, id := range ids {
		members[id] = struct{}{}
	}
	conf := 0.0
	for _, rel := range relations {
		_, fromOK := members[rel.From]
		_, toOK := members[rel.To]
		if fromOK && toOK && rel.Confidence > conf {
			conf = rel.Confidence
		}
	}
	return conf
}

func countAssets(findings []finding.Finding) int {
	seen := make(map[string]struct{})
	for _, f := range findings {
		if f.Asset != "" {
			seen[f.Asset] = struct{}{}
		}
	}
	return len(seen)
}

func maxPriority(findings []finding.Finding) finding.Priority {
	priority := finding.PrioNone
	for _, f := range findings {
		if p := f.Priority(); priorityRank(p) > priorityRank(priority) {
			priority = p
		}
	}
	return priority
}

// priorityRank orders priorities for sorting (higher = more urgent).
func priorityRank(p finding.Priority) int {
	switch p {
	case finding.PrioCritical:
		return 5
	case finding.PrioHigh:
		return 4
	case finding.PrioMedium:
		return 3
	case finding.PrioLow:
		return 2
	default:
		return 1
	}
}

// reconcileInsights sorts insights by priority (most urgent first) and
// assigns stable sequential IDs.
func reconcileInsights(insights []TriageInsight) []TriageInsight {
	sorted := append([]TriageInsight(nil), insights...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if priorityRank(sorted[i].Priority) != priorityRank(sorted[j].Priority) {
			return priorityRank(sorted[i].Priority) > priorityRank(sorted[j].Priority)
		}
		if sorted[i].Source != sorted[j].Source {
			return sorted[i].Source == SourceDeterministic
		}
		return sorted[i].Summary < sorted[j].Summary
	})
	for i := range sorted {
		sorted[i].ID = finding.ID(fmt.Sprintf("I-%d", i+1))
	}
	return sorted
}

// writeOutputs persists the triage result into OutDir.
func writeOutputs(dir string, result *Result) error {
	writeJSON := func(name string, value any) error {
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, name), data, 0644)
	}
	if err := writeJSON(FileManifest, result.Manifest); err != nil {
		return fmt.Errorf("triage: write manifest: %w", err)
	}
	if err := writeJSON(FileInsights, result.Insights); err != nil {
		return fmt.Errorf("triage: write insights: %w", err)
	}
	if err := writeJSON(FileRelations, result.Relations); err != nil {
		return fmt.Errorf("triage: write relations: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, FileReportMD), []byte(RenderMarkdown(result)), 0644); err != nil {
		return fmt.Errorf("triage: write report: %w", err)
	}
	return nil
}

// loadCache returns the previously computed triage when the input digest,
// model and prompt version all match.
func loadCache(dir, digest, model string, temperature float64) (*Result, bool) {
	data, err := os.ReadFile(filepath.Join(dir, FileManifest))
	if err != nil {
		return nil, false
	}
	var manifest TriageManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, false
	}
	if manifest.InputDigest != digest || manifest.Model != model ||
		manifest.PromptVersion != PromptVersion || manifest.Temperature != temperature {
		return nil, false
	}

	insightsData, err := os.ReadFile(filepath.Join(dir, FileInsights))
	if err != nil {
		return nil, false
	}
	var insights []TriageInsight
	if err := json.Unmarshal(insightsData, &insights); err != nil {
		return nil, false
	}
	relationsData, err := os.ReadFile(filepath.Join(dir, FileRelations))
	if err != nil {
		return nil, false
	}
	var relations []finding.FindingRelation
	if err := json.Unmarshal(relationsData, &relations); err != nil {
		return nil, false
	}

	return &Result{
		Manifest:  manifest,
		Insights:  insights,
		Relations: relations,
		Stats: Stats{
			CacheHit: true,
			Insights: len(insights),
			Rejected: manifest.Rejected,
			LLMError: manifest.LLMError,
		},
	}, true
}
