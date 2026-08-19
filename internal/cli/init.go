package cli

import (
	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/spf13/cobra"
)

func NewInitCommand(application *app.App) *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:     "init",
		GroupID: groupConfig,
		Short:   "Create default ScanForge config files",
		Long: `Creates the default configuration files in the current directory:
scanforge.yaml (profiles, tool paths, options) and scope.txt (the targets
you are authorized to scan). Scope is mandatory: scans refuse to run
without it.`,
		Example: `  scanforge init
  scanforge init --force   # overwrite existing files`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return application.Init(cmd.Context(), app.InitOptions{
				Force: force,
			})
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing files")

	return cmd
}
