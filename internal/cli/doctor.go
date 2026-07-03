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
		Use:   "doctor",
		Short: "Check local dependencies",
		RunE: func(cmd *cobra.Command, args []string) error {
			return application.Doctor(cmd.Context(), app.DoctorOptions{
				Profile: profile,
				JSON:    jsonOutput,
				Verbose: verbose,
			})
		},
	}

	cmd.Flags().StringVarP(&profile, "profile", "p", "", "Profile to validate tools for (passive or web)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results as JSON")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show detailed tool version output")

	return cmd
}
