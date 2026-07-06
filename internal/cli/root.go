package cli

import (
	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/spf13/cobra"
)

func NewRootCommand() *cobra.Command {
	var configPath string
	application := app.New("")

	cmd := &cobra.Command{
		Use:   "scanforge",
		Short: "Authorized pentest scan orchestrator",
		Long: `ScanForge is a CLI tool that orchestrates external security tools
for authorized pentest and recon workflows.`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			application.ConfigPath = configPath
		},
	}

	cmd.PersistentFlags().StringVar(&configPath, "config", "", "Path to scanforge.yaml (overrides SCANFORGE_CONFIG and ./scanforge.yaml)")

	cmd.AddCommand(NewRunCommand(application))
	cmd.AddCommand(NewDoctorCommand(application))
	cmd.AddCommand(NewInitCommand(application))
	cmd.AddCommand(NewAuthCommand(application))
	cmd.AddCommand(NewVersionCommand())

	return cmd
}
