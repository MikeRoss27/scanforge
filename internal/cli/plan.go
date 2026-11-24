package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/MikeRoss27/scanforge/internal/ui"
	"github.com/spf13/cobra"
)

func NewPlanCommand(application *app.App) *cobra.Command {
	var profile string
	var preset string
	var workflowFile string
	var scopeFile string
	var scopeMode string
	var scopeAdd []string
	var exclusions []string
	var targetsFile string
	var wp bool
	cmd := &cobra.Command{
		Use:     "plan <target>",
		GroupID: groupCore,
		Short:   "Preview the validated scan pipeline without running it",
		Long: `Validates the profile, scope and module dependencies, then prints the
execution waves (which modules run, in what order, and what each one
requires) without executing anything. Use it to sanity-check a profile
before running a scan.

A port written in the target (http://127.0.0.1:8082, https://example.com:8443
or host:8082) is shown as PORT and probed by httpx on top of 80/443. It is only
a probe hint: scope still covers the host and a port-scoped scope entry is
rejected.`,
		Example: `  scanforge plan example.com --preset deep
  scanforge plan http://127.0.0.1:8082 --scope-mode exact
  scanforge plan --targets targets.txt --profile web
  scanforge plan example.com --workflow workflows/web-recon.yaml`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// --profile takes precedence; --preset is shorthand for one of
			// the built-in profile names.
			if profile == "" {
				profile = preset
			}
			var target string
			if len(args) > 0 {
				target = args[0]
			}
			plans, err := application.Plan(app.PlanOptions{
				Target: target, TargetsFile: targetsFile, Profile: profile, Workflow: workflowFile, Scope: scopeFile,
				ScopeMode: scopeMode, ScopeAdd: scopeAdd, Exclusions: exclusions, WP: wp,
			})
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			for _, plan := range plans {
				printPlanPanel(out, plan)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&profile, "profile", "p", "", "Scan profile to inspect (default from config)")
	cmd.Flags().StringVar(&workflowFile, "workflow", "", "YAML workflow file to inspect instead of a profile")
	cmd.Flags().StringVar(&preset, "preset", "", "User-oriented preset (safe, recon, web, ports, vuln, deep, wp)")
	cmd.Flags().BoolVar(&wp, "wp", false, "Add the WordPress engagement chain to the resolved profile")
	cmd.Flags().StringVar(&targetsFile, "targets", "", "File with one target per line (multi-target engagement; exclusive with a positional target)")
	cmd.Flags().StringVarP(&scopeFile, "scope", "s", "", "Scope file (default from config)")
	cmd.Flags().StringVar(&scopeMode, "scope-mode", "", "Implicit scope mode: exact or domain (default domain for DNS domains, exact for IPs and single-label hosts)")
	cmd.Flags().StringArrayVar(&scopeAdd, "scope-add", nil, "Add an entry to implicit scope (repeatable)")
	cmd.Flags().StringArrayVar(&exclusions, "exclude", nil, "Exclude an entry from implicit scope (repeatable)")
	return cmd
}

func printPlanPanel(out io.Writer, plan *app.PlanResult) {
	kv := func(key, value string) string {
		return fmt.Sprintf("%s %s", ui.DimBold(fmt.Sprintf("%-10s", key)), value)
	}

	var info strings.Builder
	fmt.Fprintf(&info, "%s\n", kv("TARGET", ui.Bold(plan.Target)))
	fmt.Fprintf(&info, "%s\n", kv("PROFILE", ui.Secondary(plan.Profile)))
	fmt.Fprintf(&info, "%s\n", kv("SCOPE", ui.Dim(plan.Scope)))
	fmt.Fprintf(&info, "%s\n", kv("SOURCE", ui.Dim(fmt.Sprintf("%s (mode %s)", plan.ScopeSource, plan.ScopeMode))))
	for _, entry := range plan.ScopeEntries {
		fmt.Fprintf(&info, "%-10s %s\n", "", ui.Dim("• "+entry))
	}
	if plan.ProbeHint != "" {
		fmt.Fprintf(&info, "%s\n", kv("PORT", ui.Dim(plan.ProbeHint+" probed by httpx (hint from target; scope stays host-only)")))
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

	_, _ = fmt.Fprintln(out, ui.Section("Scan plan", info.String()+"\n"+table))
	_, _ = fmt.Fprintln(out)
}
