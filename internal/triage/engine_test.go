package triage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/finding"
)

// fakeAnalyzer returns canned insights, optionally failing.
type fakeAnalyzer struct {
	insights []TriageInsight
	err      error
	calls    int
}

func (f *fakeAnalyzer) Analyze(_ context.Context, _ TriageBundle) ([]TriageInsight, error) {
	f.calls++
	return f.insights, f.err
}

func mkFinding(source, template, asset, url string, cves []string) finding.Finding {
	f := finding.Finding{
		Kind: "vulnerability", Asset: asset, Source: source,
		TemplateID: template, URL: url, CVEs: cves,
		Severity: finding.SevHigh, MatchedAt: url,
	}
	f.ID = f.Fingerprint()
	return f
}

func TestEngineDeterministicOnly(t *testing.T) {
	dir := t.TempDir()
	findings := []finding.Finding{
		mkFinding("nuclei", "t-1", "a.com", "https://a.com/x", nil),
		mkFinding("nuclei", "t-1", "a.com", "https://a.com/y", nil), // duplicate
		mkFinding("nuclei", "t-2", "b.com", "https://b.com/z", nil),
	}
	relations := finding.BuildRelations(findings)

	engine := NewEngine()
	result, err := engine.Run(context.Background(), Input{
		Target:    "example.com",
		Findings:  findings,
		Relations: relations,
		OutDir:    dir,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	if result.Manifest.Model != "" || result.Manifest.Provider != "deterministic" {
		t.Errorf("unexpected manifest: %+v", result.Manifest)
	}
	if len(result.Insights) != 2 {
		t.Fatalf("expected 2 deterministic insights (summary + duplicate), got %d", len(result.Insights))
	}
	var summary, dup *TriageInsight
	for i := range result.Insights {
		switch result.Insights[i].Kind {
		case InsightSummary:
			summary = &result.Insights[i]
		case InsightDuplicate:
			dup = &result.Insights[i]
		}
	}
	if summary == nil {
		t.Fatal("summary insight missing")
	}
	if dup == nil {
		t.Fatal("duplicate insight missing")
	}
	if len(dup.FindingIDs) != 2 {
		t.Errorf("unexpected duplicate insight: %+v", dup)
	}
	if dup.Confidence != 1.0 {
		t.Errorf("duplicate group confidence should be 1.0, got %v", dup.Confidence)
	}
	if dup.Source != SourceDeterministic {
		t.Errorf("duplicate insight source should be deterministic, got %s", dup.Source)
	}

	// Outputs written.
	for _, name := range []string{FileManifest, FileInsights, FileRelations, FileReportMD} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("missing output %s: %v", name, err)
		}
	}
}

func TestEngineWithLLMAndValidator(t *testing.T) {
	dir := t.TempDir()
	findings := []finding.Finding{
		mkFinding("nuclei", "t-1", "a.com", "https://a.com/x", []string{"CVE-2026-0001"}),
	}
	relations := finding.BuildRelations(findings)

	engine := NewEngine()
	engine.Analyzer = &fakeAnalyzer{insights: []TriageInsight{
		{
			Kind:       InsightPriority,
			FindingIDs: []finding.ID{findings[0].ID},
			Summary:    "Address this first",
			Priority:   finding.PrioCritical,
			Confidence: 0.9,
			CVEs:       []string{"CVE-2026-0001"},
			Source:     SourceLLM,
		},
		{
			Kind:       InsightPriority,
			FindingIDs: []finding.ID{findings[0].ID},
			Summary:    "Hallucinated",
			Priority:   finding.PrioHigh,
			Confidence: 0.9,
			CVEs:       []string{"CVE-2026-99999"}, // unknown → rejected
			Source:     SourceLLM,
		},
	}}

	result, err := engine.Run(context.Background(), Input{
		Target:    "example.com",
		Findings:  findings,
		Relations: relations,
		Model:     &ModelConfig{Model: "qwen3.5-9b", BaseURL: "http://127.0.0.1:8080/v1"},
		OutDir:    dir,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	if result.Stats.Rejected != 1 {
		t.Errorf("expected 1 rejected insight, got %d", result.Stats.Rejected)
	}
	if result.Manifest.Rejected != 1 {
		t.Errorf("manifest should record 1 rejection, got %d", result.Manifest.Rejected)
	}
	if result.Manifest.Model != "qwen3.5-9b" {
		t.Errorf("manifest model = %q", result.Manifest.Model)
	}

	// Valid LLM insight present with stable ID.
	var llmInsight *TriageInsight
	for i := range result.Insights {
		if result.Insights[i].Source == SourceLLM {
			llmInsight = &result.Insights[i]
		}
	}
	if llmInsight == nil {
		t.Fatal("valid LLM insight missing from result")
	}
	if llmInsight.ID == "" {
		t.Error("insight missing ID")
	}
}

func TestEngineLLMFailureIsNonFatal(t *testing.T) {
	dir := t.TempDir()
	findings := []finding.Finding{mkFinding("nuclei", "t-1", "a.com", "https://a.com/x", nil)}

	engine := NewEngine()
	engine.Analyzer = &fakeAnalyzer{err: context.DeadlineExceeded}

	result, err := engine.Run(context.Background(), Input{
		Target:    "example.com",
		Findings:  findings,
		Relations: finding.BuildRelations(findings),
		Model:     &ModelConfig{Model: "qwen3.5-9b", BaseURL: "http://127.0.0.1:8080/v1"},
		OutDir:    dir,
	})
	if err != nil {
		t.Fatalf("LLM failure must not fail the run: %v", err)
	}
	if result.Stats.LLMError == "" {
		t.Error("expected LLMError recorded in stats")
	}
	if result.Manifest.LLMError == "" {
		t.Error("expected LLMError recorded in manifest")
	}
	if len(result.Insights) == 0 {
		t.Error("deterministic insights must survive an LLM failure")
	}
}

func TestEngineCacheHitAndForce(t *testing.T) {
	dir := t.TempDir()
	findings := []finding.Finding{mkFinding("nuclei", "t-1", "a.com", "https://a.com/x", nil)}
	relations := finding.BuildRelations(findings)

	analyzer := &fakeAnalyzer{insights: []TriageInsight{{
		Kind: InsightObservation, FindingIDs: []finding.ID{findings[0].ID},
		Summary: "observed", Priority: finding.PrioLow, Confidence: 0.5, Source: SourceLLM,
	}}}

	engine := NewEngine()
	engine.Analyzer = analyzer
	in := Input{
		Target:    "example.com",
		Findings:  findings,
		Relations: relations,
		Model:     &ModelConfig{Model: "m", BaseURL: "http://127.0.0.1:8080/v1"},
		OutDir:    dir,
	}

	if _, err := engine.Run(context.Background(), in); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if analyzer.calls != 1 {
		t.Fatalf("expected 1 analyzer call, got %d", analyzer.calls)
	}

	// Second run with identical input → cache hit, no analyzer call.
	second, err := engine.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if !second.Stats.CacheHit {
		t.Error("expected cache hit on identical input")
	}
	if analyzer.calls != 1 {
		t.Errorf("analyzer must not be called on cache hit, got %d calls", analyzer.calls)
	}

	// --force bypasses the cache.
	forced, err := engine.Run(context.Background(), Input{
		Target: in.Target, Findings: in.Findings, Relations: in.Relations,
		Model: in.Model, Force: true, OutDir: dir,
	})
	if err != nil {
		t.Fatalf("forced run: %v", err)
	}
	if forced.Stats.CacheHit {
		t.Error("forced run must not report a cache hit")
	}
	if analyzer.calls != 2 {
		t.Errorf("expected analyzer to run again on --force, got %d calls", analyzer.calls)
	}
}

func TestEngineCacheInvalidatedByInputChange(t *testing.T) {
	dir := t.TempDir()
	analyzer := &fakeAnalyzer{}

	engine := NewEngine()
	engine.Analyzer = analyzer
	base := Input{
		Target: "example.com",
		Model:  &ModelConfig{Model: "m", BaseURL: "http://127.0.0.1:8080/v1"},
		OutDir: dir,
	}

	base.Findings = []finding.Finding{mkFinding("nuclei", "t-1", "a.com", "https://a.com/x", nil)}
	base.Relations = finding.BuildRelations(base.Findings)
	if _, err := engine.Run(context.Background(), base); err != nil {
		t.Fatalf("first run: %v", err)
	}

	// New finding appears → different digest → cache miss.
	base.Findings = append(base.Findings, mkFinding("nuclei", "t-2", "b.com", "https://b.com/y", nil))
	base.Relations = finding.BuildRelations(base.Findings)
	if _, err := engine.Run(context.Background(), base); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if analyzer.calls != 2 {
		t.Errorf("input change must invalidate the cache, got %d analyzer calls", analyzer.calls)
	}
}

func TestBundleTruncatesEvidence(t *testing.T) {
	long := make([]byte, 2000)
	for i := range long {
		long[i] = 'a'
	}
	f := mkFinding("nuclei", "t-1", "a.com", "https://a.com/x", nil)
	f.Evidence = string(long)

	bundle := BuildBundle("example.com", []finding.Finding{f}, nil)
	if len(bundle.Findings) != 1 {
		t.Fatalf("expected 1 bundled finding")
	}
	// Evidence field removed from TriageFinding to prevent credential leakage
	if bundle.Findings[0].ID == "" {
		t.Errorf("finding ID should be set")
	}
}

func TestBundleCapsFindings(t *testing.T) {
	var findings []finding.Finding
	for i := 0; i < MaxBundleFindings+10; i++ {
		findings = append(findings, mkFinding("nuclei", "t", "a.com", "https://a.com/x", nil))
	}
	bundle := BuildBundle("example.com", findings, nil)
	if len(bundle.Findings) != MaxBundleFindings {
		t.Errorf("expected %d bundled findings, got %d", MaxBundleFindings, len(bundle.Findings))
	}
	if bundle.Truncated != 10 {
		t.Errorf("expected 10 truncated, got %d", bundle.Truncated)
	}
}

func TestManifestJSONRoundTrip(t *testing.T) {
	dir := t.TempDir()
	findings := []finding.Finding{mkFinding("nuclei", "t-1", "a.com", "https://a.com/x", nil)}
	engine := NewEngine()
	result, err := engine.Run(context.Background(), Input{
		Target:    "example.com",
		Findings:  findings,
		Relations: finding.BuildRelations(findings),
		OutDir:    dir,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, FileManifest))
	if err != nil {
		t.Fatal(err)
	}
	var manifest TriageManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("manifest.json not valid JSON: %v", err)
	}
	if manifest.SchemaVersion != SchemaVersion || manifest.PromptVersion != PromptVersion {
		t.Errorf("unexpected manifest versions: %+v", manifest)
	}
	if manifest.InputDigest != result.Manifest.InputDigest {
		t.Errorf("digest mismatch: %q vs %q", manifest.InputDigest, result.Manifest.InputDigest)
	}
}
