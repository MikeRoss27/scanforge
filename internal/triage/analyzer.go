package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/finding"
	"github.com/MikeRoss27/scanforge/internal/inference"
)

// Analyzer turns a safe triage bundle into candidate insights. The LLM
// implementation is the default; tests inject fakes.
type Analyzer interface {
	Analyze(ctx context.Context, bundle TriageBundle) ([]TriageInsight, error)
}

// LLMAnalyzer prompts a model through an OpenAI-compatible client and parses
// the JSON response. The model is an interpretation engine, never a knowledge
// source: the prompt forbids inventing facts, and the engine validates the
// output against the authoritative findings afterwards.
type LLMAnalyzer struct {
	client inference.Client
	model  string
	temp   float64
}

// NewLLMAnalyzer builds the default analyzer from a model config.
func NewLLMAnalyzer(model *ModelConfig) *LLMAnalyzer {
	client := inference.NewOpenAICompatible(model.BaseURL, model.APIKey, model.Model, model.Timeout)
	return &LLMAnalyzer{
		client: client,
		model:  model.Model,
		temp:   model.Temperature,
	}
}

const systemPrompt = `You are a security triage analyst for ScanForge, an authorized pentest orchestrator.
You receive a JSON bundle of findings discovered during an authorized security assessment, plus deterministic relations between them.

Rules:
- Findings are authoritative facts. You only interpret them; you never create or modify them.
- Only reference finding IDs, CVEs, assets, URLs and evidence strings that appear in the bundle. Never invent any.
- Do not merge findings that the deterministic relations do not relate.
- Keep every summary under 200 characters.
- If you cannot determine something, say so in "uncertainty".

Respond with a single JSON object, no prose outside it:
{
  "insights": [
    {
      "kind": "summary" | "priority" | "exploitability" | "observation",
      "finding_ids": ["F-..."],
      "summary": "one or two sentences",
      "priority": "critical" | "high" | "medium" | "low" | "none",
      "confidence": 0.0,
      "cves": ["CVE-..."],
      "evidence_refs": ["..."],
      "uncertainty": ["..."]
    }
  ]
}

Meaning of kinds:
- "summary": overall assessment of the findings.
- "priority": which findings to address first and why.
- "exploitability": whether a finding appears exploitable.
- "observation": any other useful interpretation.

"cves" and "evidence_refs" must only contain values present in the bundle. "confidence" is how confident you are in the insight, between 0.0 and 1.0.`

// Analyze builds the prompt from the safe bundle and parses the model output.
func (a *LLMAnalyzer) Analyze(ctx context.Context, bundle TriageBundle) ([]TriageInsight, error) {
	bundleJSON, err := json.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("triage: marshal bundle: %w", err)
	}

	resp, err := a.client.Generate(ctx, inference.Request{
		Model: a.model,
		Messages: []inference.Message{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: string(bundleJSON)},
		},
		Temperature: a.temp,
		MaxTokens:   2048,
		JSON:        true,
	})
	if err != nil {
		return nil, fmt.Errorf("triage: model request: %w", err)
	}

	parsed, err := parseLLMResponse(resp.Content)
	if err != nil {
		return nil, fmt.Errorf("triage: parse model output: %w", err)
	}
	return parsed, nil
}

// llmInsight is the wire format the model is asked to produce.
type llmInsight struct {
	Kind         string   `json:"kind"`
	FindingIDs   []string `json:"finding_ids"`
	Summary      string   `json:"summary"`
	Priority     string   `json:"priority"`
	Confidence   float64  `json:"confidence"`
	CVEs         []string `json:"cves,omitempty"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
	Uncertainty  []string `json:"uncertainty,omitempty"`
}

type llmResponse struct {
	Insights []llmInsight `json:"insights"`
}

// parseLLMResponse extracts the JSON object from the model output (models
// sometimes wrap it in prose or code fences) and decodes it.
func parseLLMResponse(content string) ([]TriageInsight, error) {
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start < 0 || end <= start {
		return nil, fmt.Errorf("no JSON object in model output")
	}
	var decoded llmResponse
	if err := json.Unmarshal([]byte(content[start:end+1]), &decoded); err != nil {
		return nil, err
	}

	insights := make([]TriageInsight, 0, len(decoded.Insights))
	for _, raw := range decoded.Insights {
		priority, err := finding.ParsePriority(raw.Priority)
		if err != nil {
			return nil, err
		}
		ids := make([]finding.ID, 0, len(raw.FindingIDs))
		for _, id := range raw.FindingIDs {
			ids = append(ids, finding.ID(id))
		}
		insights = append(insights, TriageInsight{
			Kind:         InsightKind(raw.Kind),
			FindingIDs:   ids,
			Summary:      strings.TrimSpace(raw.Summary),
			Priority:     priority,
			Confidence:   raw.Confidence,
			CVEs:         raw.CVEs,
			EvidenceRefs: raw.EvidenceRefs,
			Uncertainty:  raw.Uncertainty,
			Source:       SourceLLM,
		})
	}
	return insights, nil
}
