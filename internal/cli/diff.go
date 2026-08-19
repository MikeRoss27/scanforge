package cli

import (
	"encoding/json"
	"fmt"

	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/MikeRoss27/scanforge/internal/ui"
	"github.com/spf13/cobra"
)

func NewDiffCommand(application *app.App) *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:     "diff <run1> <run2>",
		GroupID: groupReports,
		Short:   "Show what changed between two runs of the same target",
		Long: "Loads the two run directories (runs/<target>/<timestamp>), " +
			"reconsolidates their reports from the raw artifacts and lists the " +
			"assets, ports and vulnerabilities that appeared or disappeared.",
		Example: `  scanforge diff runs/example.com/2026-08-18T10:00:00Z runs/example.com/2026-08-19T10:00:00Z
  scanforge diff runs/example.com/2026-08-18T10:00:00Z runs/example.com/2026-08-19T10:00:00Z --json`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			delta, rendered, err := application.Diff(cmd.Context(), app.DiffOptions{
				Run1: args[0],
				Run2: args[1],
			})
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if jsonOut {
				data, err := json.MarshalIndent(delta, "", "  ")
				if err != nil {
					return err
				}
				_, err = fmt.Fprintln(out, string(data))
				return err
			}
			_, err = fmt.Fprintln(out, ui.Panel("🔍 RUN DIFF", ui.Primary(rendered)))
			return err
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit the delta as JSON (for CI)")
	return cmd
}
