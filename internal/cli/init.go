package cli

import (
	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/spf13/cobra"
)

func NewInitCommand(application *app.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create default ScanForge config files",
		RunE: func(cmd *cobra.Command, args []string) error {
			return application.Init(cmd.Context())
		},
	}

	return cmd
}
