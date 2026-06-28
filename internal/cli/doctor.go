package cli

import (
	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/spf13/cobra"
)

func NewDoctorCommand(application *app.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check local dependencies",
		RunE: func(cmd *cobra.Command, args []string) error {
			return application.Doctor(cmd.Context())
		},
	}

	return cmd
}
