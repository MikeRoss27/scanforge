package cli

import (
	"fmt"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

func NewPlanCommand(application *app.App) *cobra.Command {
	var profile string
	var scopeFile string
	var scopeMode string
	var scopeAdd []string
	var exclusions []string
	cmd := &cobra.Command{
		Use:   "plan <target>",
		Short: "Show the validated scan pipeline without creating a run",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			plan, err := application.Plan(app.PlanOptions{
				Target: args[0], Profile: profile, Scope: scopeFile,
				ScopeMode: scopeMode, ScopeAdd: scopeAdd, Exclusions: exclusions,
			})
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()

			fmt.Fprintf(
				out,
				"Target:       %s\nProfile:      %s\nScope source: %s\nScope mode:   %s\nScope input:  %s\nScope entries:\n",
				plan.Target, plan.Profile, plan.ScopeSource, plan.ScopeMode, plan.Scope,
			)
			for _, entry := range plan.ScopeEntries {
				fmt.Fprintf(out, "  - %s\n", entry)
			}
			if plan.ScopeNote != "" {
				fmt.Fprintf(out, "Scope note:   %s\n", plan.ScopeNote)
			}
			fmt.Fprintln(out)

			rows := pterm.TableData{{"WAVE", "MODULE", "RISK", "REQUIRES"}}
			for _, step := range plan.Steps {
				requires := "-"
				if len(step.Requires) > 0 {
					requires = strings.Join(step.Requires, ", ")
				}
				rows = append(rows, []string{
					fmt.Sprintf("%d", step.Wave),
					step.Name,
					colorizeRisk(step.Risk),
					requires,
				})
			}
			return pterm.DefaultTable.WithHasHeader().WithBoxed().WithWriter(out).WithData(rows).Render()
		},
	}
	cmd.Flags().StringVarP(&profile, "profile", "p", "", "Scan preset/profile to inspect")
	cmd.Flags().StringVar(&profile, "preset", "", "User-oriented preset (safe, recon, web, ports, vuln, deep)")
	cmd.Flags().StringVarP(&scopeFile, "scope", "s", "", "Scope file (default from config)")
	cmd.Flags().StringVar(&scopeMode, "scope-mode", "", "Implicit scope mode: exact or domain (default exact)")
	cmd.Flags().StringArrayVar(&scopeAdd, "scope-add", nil, "Add an entry to implicit scope (repeatable)")
	cmd.Flags().StringArrayVar(&exclusions, "exclude", nil, "Exclude an entry from implicit scope (repeatable)")
	return cmd
}

func colorizeRisk(risk string) string {
	switch risk {
	case "passive":
		return pterm.FgGreen.Sprint(risk)
	case "active-low":
		return pterm.FgCyan.Sprint(risk)
	case "active":
		return pterm.FgYellow.Sprint(risk)
	case "active-high":
		return pterm.FgRed.Sprint(risk)
	default:
		return pterm.FgGray.Sprint(risk)
	}
}
