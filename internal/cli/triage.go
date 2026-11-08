package cli

import (
	"fmt"

	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/MikeRoss27/scanforge/internal/triage"
	"github.com/MikeRoss27/scanforge/internal/ui"
	"github.com/spf13/cobra"
)

func NewTriageCommand(application *app.App) *cobra.Command {
	var force bool
	var model string
	var baseURL string
	cmd := &cobra.Command{
		Use:     "triage <run>",
		GroupID: groupReports,
		Short:   "Analyze and prioritize the findings of a run",
		Long: "Projects the consolidated report of a run directory " +
			"(runs/<target>/<timestamp>) into canonical findings, computes the " +
			"deterministic duplicate/relation groups and, when an LLM backend is " +
			"configured (ai: in scanforge.yaml), produces validated AI insights. " +
			"Results are written under <run>/triage/.",
		Example: `  scanforge triage runs/example.com/2026-08-19T10:00:00Z
  scanforge triage runs/example.com/2026-08-19T10:00:00Z --force
  scanforge triage runs/example.com/2026-08-19T10:00:00Z --model qwen3.5-9b`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := application.Triage(cmd.Context(), app.TriageOptions{
				Run:     args[0],
				Force:   force,
				Model:   model,
				BaseURL: baseURL,
			})
			if err != nil {
				return err
			}
			printTriageSummary(cmd, result)
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Re-run the analysis even when the cached result is still valid")
	cmd.Flags().StringVar(&model, "model", "", "Model name (overrides ai.model in scanforge.yaml)")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "OpenAI-compatible base URL (overrides ai.base_url)")
	return cmd
}

func printTriageSummary(cmd *cobra.Command, result *triage.Result) {
	out := cmd.OutOrStdout()
	var body string

	model := result.Manifest.Model
	if model == "" {
		model = "deterministic"
	}
	body += fmt.Sprintf("Model:        %s\n", ui.Primary(model))
	body += fmt.Sprintf("Findings:     %d\n", result.Stats.Findings)
	body += fmt.Sprintf("Relations:    %d\n", result.Stats.Relations)
	body += fmt.Sprintf("Insights:     %d\n", result.Stats.Insights)
	if result.Stats.LLMInsights > 0 {
		body += fmt.Sprintf("LLM insights: %d\n", result.Stats.LLMInsights)
	}
	if result.Stats.Rejected > 0 {
		body += fmt.Sprintf("Rejected:     %s\n", ui.Yellow(fmt.Sprintf("%d", result.Stats.Rejected)))
	}
	if result.Stats.CacheHit {
		body += fmt.Sprintf("Cache:        %s\n", ui.Green("hit"))
	}
	if result.Stats.LLMError != "" {
		body += fmt.Sprintf("LLM error:    %s\n", ui.Red(result.Stats.LLMError))
	}
	body += fmt.Sprintf("\n%s %s\n", ui.Green("✓ triage written to"), ui.Primary(result.Dir))

	_, _ = fmt.Fprintln(out, ui.Panel("🧠 TRIAGE", body))
}
