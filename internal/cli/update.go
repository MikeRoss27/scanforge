package cli

import (
	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/spf13/cobra"
)

func NewUpdateCommand(application *app.App) *cobra.Command {
	var opts app.UpdateOptions

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update scanforge and its dependencies",
		Long:  `Update scanforge to the latest version via go install. You can also update external tools using the --tools flag.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return application.Update(cmd.Context(), opts)
		},
	}

	cmd.Flags().BoolVar(&opts.Tools, "tools", false, "Update external tools (subfinder, nuclei, etc.) as well")

	return cmd
}
