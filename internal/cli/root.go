// Package cli defines the cobra command tree for scanforge.
package cli

import (
	"strings"

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
		Long:  "ScanForge runs scope-validated security scans and saves consolidated reports.",
		Example: `  scanforge run example.com --profile web --confirm-scope
  scanforge plan example.com --preset deep
  scanforge diff runs/<target>/<run-a> runs/<target>/<run-b>
  scanforge doctor --profile web`,
		// Runtime errors (a failed module, a deadlock, ...) must not dump
		// the full flag reference: the scan summary already explains what
		// happened. Errors are printed once by cmd/scanforge/main.go.
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			application.ConfigPath = configPath
		},
	}

	// Colored, section-aligned help for the whole command tree; child
	// commands inherit the renderer through Cobra's HelpFunc lookup.
	cmd.SetHelpFunc(renderColoredHelp)

	// Keep the parse error visible and point to help for the affected command.
	cmd.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		c.PrintErrf("See %q for usage.\n", c.CommandPath()+" --help")
		return err
	})

	// Keep commands in a logical order instead of alphabetical.
	cobra.EnableCommandSorting = false

	cmd.AddGroup(&cobra.Group{ID: groupCore, Title: "Core Commands:"})
	cmd.AddGroup(&cobra.Group{ID: groupReports, Title: "Reports & Analysis:"})
	cmd.AddGroup(&cobra.Group{ID: groupConfig, Title: "Configuration:"})
	cmd.AddGroup(&cobra.Group{ID: groupMaintenance, Title: "Maintenance:"})

	cmd.PersistentFlags().StringVar(&configPath, "config", "", "Config (default: SCANFORGE_CONFIG or scanforge.yaml)")

	run := NewRunCommand(application)
	run.SetUsageTemplate(strings.Replace(cmd.UsageTemplate(),
		"Flags:\n{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}",
		"{{runFlagHelp .}}", 1))
	cmd.AddCommand(run)
	cmd.AddCommand(NewPlanCommand(application))
	cmd.AddCommand(NewDiffCommand(application))
	cmd.AddCommand(NewExportCommand(application))
	cmd.AddCommand(NewTriageCommand(application))
	cmd.AddCommand(NewMCPCommand(application))
	cmd.AddCommand(NewAPICommand(application))
	cmd.AddCommand(NewInitCommand(application))
	cmd.AddCommand(NewAuthCommand(application))
	cmd.AddCommand(NewConfigCommand(application))
	cmd.AddCommand(NewDoctorCommand(application))
	cmd.AddCommand(NewBenchmarkCommand(application))
	cmd.AddCommand(NewUpdateCommand(application))
	cmd.AddCommand(NewVersionCommand())

	return cmd
}
