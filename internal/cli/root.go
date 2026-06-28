package cli

import (
	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/spf13/cobra"
)

func NewRootCommand() *cobra.Command {
	application := app.New()

	cmd := &cobra.Command{
		Use:   "scanforge",
		Short: "Authorized pentest scan orchestrator",
		Long: `ScanForge is a CLI tool that orchestrates external security tools
for authorized pentest and recon workflows.`,
	}

	cmd.AddCommand(NewRunCommand(application))
	cmd.AddCommand(NewDoctorCommand(application))
	cmd.AddCommand(NewInitCommand(application))

	return cmd
}
