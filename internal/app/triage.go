package app

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/MikeRoss27/scanforge/internal/finding"
	"github.com/MikeRoss27/scanforge/internal/report"
	"github.com/MikeRoss27/scanforge/internal/storage"
	"github.com/MikeRoss27/scanforge/internal/triage"
)

// TriageOptions selects the run to analyze and optional LLM overrides.
type TriageOptions struct {
	// Run is a run root directory (runs/<target>/<id>).
	Run string
	// Force bypasses the cache and re-runs the analysis.
	Force bool
	// Model and BaseURL override the ai section of scanforge.yaml.
	Model   string
	BaseURL string
}

// Triage reconsolidates a run's report, projects it into the canonical
// finding model, computes the deterministic relations and runs the triage
// pipeline (deduplication + optional LLM analysis). Results are written under
// <run>/triage/ and returned for rendering.
func (a *App) Triage(ctx context.Context, opts TriageOptions) (*triage.Result, error) {
	run, err := storage.OpenRun(opts.Run)
	if err != nil {
		return nil, err
	}
	rep, err := report.GenerateReport(opts.Run, &run.Manifest)
	if err != nil {
		return nil, fmt.Errorf("generate report for %s: %w", opts.Run, err)
	}

	findings := finding.FromReport(rep)
	relations := finding.BuildRelations(findings)

	cfg, err := a.loadConfig()
	if err != nil {
		return nil, err
	}

	var model *triage.ModelConfig
	if opts.Model != "" || opts.BaseURL != "" || cfg.AI.Model != "" || cfg.AI.BaseURL != "" {
		model = &triage.ModelConfig{
			BaseURL:     firstNonEmpty(opts.BaseURL, cfg.AI.BaseURL),
			Model:       firstNonEmpty(opts.Model, cfg.AI.Model),
			APIKey:      cfg.AI.APIKey,
			Timeout:     cfg.AI.Timeout,
			Temperature: cfg.AI.Temperature,
		}
		if model.BaseURL == "" || model.Model == "" {
			return nil, fmt.Errorf("LLM triage requires ai.base_url and ai.model in scanforge.yaml (or --model/--base-url); omit them to run deterministic-only triage")
		}
	}

	engine := triage.NewEngine()
	return engine.Run(ctx, triage.Input{
		Target:    run.Target,
		Findings:  findings,
		Relations: relations,
		Model:     model,
		Force:     opts.Force,
		OutDir:    filepath.Join(run.RootDir, "triage"),
	})
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
