// Package cli defines the cobra command tree for scanforge.
package cli

import (
	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/spf13/cobra"
)

// Command group IDs used to organize the root help output.
const (
	groupCore        = "core"
	groupReports     = "reports"
	groupConfig      = "config"
	groupMaintenance = "maintenance"
)

func NewRootCommand() *cobra.Command {
	var configPath string
	application := app.New("")

	cmd := &cobra.Command{
		Use:   "scanforge",
		Short: "Authorized pentest scan orchestrator",
		Long: `ScanForge orchestrates external security tools (subfinder, dnsx, httpx,
nuclei, ...) into a single, scope-enforced pipeline for authorized pentest
and recon engagements.

Every target is validated against scope.txt before any tool runs, and each
scan produces a consolidated report under runs/<target>/<timestamp>/.

Typical workflow:
  scanforge init     create scanforge.yaml and scope.txt
  scanforge doctor   verify that the required tools are installed
  scanforge plan     preview the validated pipeline without running it
  scanforge run      execute the scan and produce a report
  scanforge diff     compare two runs to track changes over time`,
		// Runtime errors (a failed module, a deadlock, ...) must not dump
		// the full flag reference: the scan summary already explains what
		// happened. Errors are printed once by cmd/scanforge/main.go.
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			application.ConfigPath = configPath
		},
	}

	// Flag-parsing mistakes are still a usage problem: keep showing help
	// there so the user sees what flags exist.
	cmd.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		c.PrintErrln(c.UsageString())
		return err
	})

	// Keep commands in a logical order instead of alphabetical.
	cobra.EnableCommandSorting = false

	cmd.AddGroup(&cobra.Group{ID: groupCore, Title: "Core Commands:"})
	cmd.AddGroup(&cobra.Group{ID: groupReports, Title: "Reports & Analysis:"})
	cmd.AddGroup(&cobra.Group{ID: groupConfig, Title: "Configuration:"})
	cmd.AddGroup(&cobra.Group{ID: groupMaintenance, Title: "Maintenance:"})

	cmd.PersistentFlags().StringVar(&configPath, "config", "", "Path to scanforge.yaml (overrides SCANFORGE_CONFIG and ./scanforge.yaml)")

	cmd.AddCommand(NewRunCommand(application))
	cmd.AddCommand(NewPlanCommand(application))
	cmd.AddCommand(NewDiffCommand(application))
	cmd.AddCommand(NewExportCommand(application))
	cmd.AddCommand(NewInitCommand(application))
	cmd.AddCommand(NewAuthCommand(application))
	cmd.AddCommand(NewConfigCommand(application))
	cmd.AddCommand(NewDoctorCommand(application))
	cmd.AddCommand(NewUpdateCommand(application))
	cmd.AddCommand(NewVersionCommand())

	return cmd
}
