package cli

import (
	"fmt"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/MikeRoss27/scanforge/internal/ui"
	"github.com/spf13/cobra"
)

func NewPlanCommand(application *app.App) *cobra.Command {
	var profile string
	var preset string
	var scopeFile string
	var scopeMode string
	var scopeAdd []string
	var exclusions []string
	cmd := &cobra.Command{
		Use:   "plan <target>",
		Short: "Show the validated scan pipeline without creating a run",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// --profile takes precedence; --preset is shorthand for one of
			// the built-in profile names.
			if profile == "" {
				profile = preset
			}
			plan, err := application.Plan(app.PlanOptions{
				Target: args[0], Profile: profile, Scope: scopeFile,
				ScopeMode: scopeMode, ScopeAdd: scopeAdd, Exclusions: exclusions,
			})
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()

			kv := func(key, value string) string {
				return fmt.Sprintf("%-10s %s", ui.DimBold(key), value)
			}

			var info strings.Builder
			fmt.Fprintf(&info, "%s\n", kv("TARGET", ui.Primary(plan.Target)))
			fmt.Fprintf(&info, "%s\n", kv("PROFILE", ui.Secondary(plan.Profile)))
			fmt.Fprintf(&info, "%s\n", kv("SCOPE", ui.Dim(plan.Scope)))
			fmt.Fprintf(&info, "%s\n", kv("SOURCE", ui.Dim(fmt.Sprintf("%s (mode %s)", plan.ScopeSource, plan.ScopeMode))))
			for _, entry := range plan.ScopeEntries {
				fmt.Fprintf(&info, "%-10s %s\n", "", ui.Dim("• "+entry))
			}
			if plan.ScopeNote != "" {
				fmt.Fprintf(&info, "%s\n", kv("NOTE", ui.Yellow(plan.ScopeNote)))
			}

			var rows [][]string
			for _, step := range plan.Steps {
				requires := "-"
				if len(step.Requires) > 0 {
					requires = strings.Join(step.Requires, ", ")
				}
				rows = append(rows, []string{
					fmt.Sprintf("%d", step.Wave),
					step.Name,
					ui.ColorizeRisk(step.Risk),
					requires,
				})
			}
			table := ui.Table([]string{"WAVE", "MODULE", "RISK", "REQUIRES"}, rows)

			_, err = fmt.Fprintln(out, ui.PanelWith("⚙ SCAN PLAN", info.String()+"\n"+table, ui.Accent, ui.Accent))
			return err
		},
	}
	cmd.Flags().StringVarP(&profile, "profile", "p", "", "Scan preset/profile to inspect")
	cmd.Flags().StringVar(&preset, "preset", "", "User-oriented preset (safe, recon, web, ports, vuln, deep)")
	cmd.Flags().StringVarP(&scopeFile, "scope", "s", "", "Scope file (default from config)")
	cmd.Flags().StringVar(&scopeMode, "scope-mode", "", "Implicit scope mode: exact or domain (default exact)")
	cmd.Flags().StringArrayVar(&scopeAdd, "scope-add", nil, "Add an entry to implicit scope (repeatable)")
	cmd.Flags().StringArrayVar(&exclusions, "exclude", nil, "Exclude an entry from implicit scope (repeatable)")
	return cmd
}
