package cli

import (
	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/spf13/cobra"
)

func NewUpdateCommand(application *app.App) *cobra.Command {
	var opts app.UpdateOptions

	cmd := &cobra.Command{
		Use:     "update",
		GroupID: groupMaintenance,
		Short:   "Update scanforge to the latest release",
		Long: `Update scanforge to the latest release, replacing the running binary.
You can also update external tools using the --tools flag.`,
		Example: `  scanforge update
  scanforge update --tools   # also update subfinder, nuclei, ...`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return application.Update(cmd.Context(), opts)
		},
	}

	cmd.Flags().BoolVar(&opts.Tools, "tools", false, "Update external tools (subfinder, nuclei, etc.) as well")

	return cmd
}
