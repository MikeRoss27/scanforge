package cli

import (
	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/spf13/cobra"
)

func NewConfigCommand(application *app.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "config",
		GroupID: groupConfig,
		Short:   "Inspect and validate scanforge.yaml",
		Long:    `Inspect and validate the scanforge.yaml configuration file.`,
	}

	cmd.AddCommand(NewConfigValidateCommand(application))

	return cmd
}

func NewConfigValidateCommand(application *app.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate scanforge.yaml",
		Long: `Loads scanforge.yaml and checks that it is usable: supported config
version, resolvable default profile, profiles referencing only known
modules, custom tool paths that exist on disk, and a parseable default
scope file.

Exits with a non-zero status when problems are found.`,
		Example: `  scanforge config validate
  scanforge config validate --config /etc/scanforge.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := application.ValidateConfig(cmd.Context())
			if err != nil {
				return err
			}
			return application.PrintValidateConfig(result)
		},
	}

	return cmd
}
