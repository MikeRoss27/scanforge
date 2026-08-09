package cli

import (
	"fmt"

	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/MikeRoss27/scanforge/internal/ui"
	"github.com/spf13/cobra"
)

func NewExportCommand(application *app.App) *cobra.Command {
	var format string
	var out string
	cmd := &cobra.Command{
		Use:   "export <run>",
		Short: "Export a run report in a machine-readable format",
		Long: "Reconsolidates the report of a run directory " +
			"(runs/<target>/<timestamp>) and writes it as SARIF 2.1.0 " +
			"(GitHub code scanning, GitLab SAST) or as DefectDojo generic " +
			"findings for import-scan.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			exportFormat, err := app.ParseExportFormat(format)
			if err != nil {
				return err
			}
			path, err := application.Export(cmd.Context(), app.ExportOptions{
				Run:    args[0],
				Format: exportFormat,
				Out:    out,
			})
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n",
				ui.Green("✓ exported to"), ui.Primary(path))
			return err
		},
	}
	cmd.Flags().StringVar(&format, "format", "sarif", "Export format: sarif or defectdojo")
	cmd.Flags().StringVarP(&out, "out", "o", "", "Output file (default: <run>/report.sarif or <run>/report.defectdojo.json)")
	return cmd
}
