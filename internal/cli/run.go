package cli

import (
	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/spf13/cobra"
)

func NewRunCommand(application *app.App) *cobra.Command {
	var profile string
	var scopeFile string
	var dryRun bool
	var verbose bool

	cmd := &cobra.Command{
		Use:   "run <target>",
		Short: "Run a scan profile against an authorized target",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return application.Run(cmd.Context(), app.RunOptions{
				Target:  args[0],
				Profile: profile,
				Scope:   scopeFile,
				DryRun:  dryRun,
				Verbose: verbose,
			})
		},
	}

	cmd.Flags().StringVarP(&profile, "profile", "p", "", "Scan profile to run (default from config)")
	cmd.Flags().StringVarP(&scopeFile, "scope", "s", "", "Scope file (default from config)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print commands without executing them")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	return cmd
}
