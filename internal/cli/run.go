package cli

import (
	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/spf13/cobra"
)

func NewRunCommand(application *app.App) *cobra.Command {
	var profile string
	var scopeFile string
	var scopeMode string
	var scopeAdd []string
	var exclusions []string
	var confirmScope bool
	var dryRun bool
	var verbose bool

	cmd := &cobra.Command{
		Use:     "run <target>",
		Aliases: []string{"scan"},
		Short:   "Run a scan profile against an authorized target",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return application.Run(cmd.Context(), app.RunOptions{
				Target:       args[0],
				Profile:      profile,
				Scope:        scopeFile,
				ScopeMode:    scopeMode,
				ScopeAdd:     scopeAdd,
				Exclusions:   exclusions,
				ConfirmScope: confirmScope,
				DryRun:       dryRun,
				Verbose:      verbose,
			})
		},
	}

	cmd.Flags().StringVarP(&profile, "profile", "p", "", "Scan profile to run (default from config)")
	cmd.Flags().StringVar(&profile, "preset", "", "User-oriented preset (safe, recon, web, ports, vuln, deep)")
	cmd.Flags().StringVarP(&scopeFile, "scope", "s", "", "Scope file (default from config)")
	cmd.Flags().StringVar(&scopeMode, "scope-mode", "", "Implicit scope mode: exact or domain (default exact)")
	cmd.Flags().StringArrayVar(&scopeAdd, "scope-add", nil, "Add an entry to implicit scope (repeatable)")
	cmd.Flags().StringArrayVar(&exclusions, "exclude", nil, "Exclude an entry from implicit scope (repeatable)")
	cmd.Flags().BoolVar(&confirmScope, "confirm-scope", false, "Confirm the effective scope non-interactively (required in CI)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print commands without executing them")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	return cmd
}
