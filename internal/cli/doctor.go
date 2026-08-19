package cli

import (
	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/spf13/cobra"
)

func NewDoctorCommand(application *app.App) *cobra.Command {
	var profile string
	var jsonOutput bool
	var verbose bool

	cmd := &cobra.Command{
		Use:     "doctor",
		GroupID: groupConfig,
		Short:   "Check local dependencies and configuration",
		Long: `Verifies that the external tools required by the selected profile are
installed and that the workspace is ready for a scan (writable runs
directory, scanforge.yaml and scope.txt present).`,
		Example: `  scanforge doctor
  scanforge doctor --profile web
  scanforge doctor --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return application.Doctor(cmd.Context(), app.DoctorOptions{
				Profile: profile,
				JSON:    jsonOutput,
				Verbose: verbose,
			})
		},
	}

	cmd.Flags().StringVarP(&profile, "profile", "p", "", "Profile or preset whose tools should be validated")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results as JSON")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show detailed tool version output")

	return cmd
}
