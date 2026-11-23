package cli

import (
	"fmt"

	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/spf13/cobra"
)

// NewWorkflowCommand groups the declarative workflow subcommands.
func NewWorkflowCommand(application *app.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "workflow",
		GroupID: groupCore,
		Short:   "Manage declarative YAML workflows",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "validate <file.yaml>",
		Short: "Validate a workflow without running anything",
		Long: `Parses the workflow and checks it against the registered modules:
unknown modules, duplicate ids, unknown or cyclic needs, needs inconsistent
with the modules' artifacts, bad durations and invalid params. Nothing is
executed and no run directory is created.`,
		Example: `  scanforge workflow validate workflows/web-recon.yaml`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := application.ValidateWorkflow(args[0])
			if err != nil {
				return fmt.Errorf("invalid workflow: %w", err)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "workflow %q is valid: %d steps\n", c.Name, len(c.Modules))
			for _, s := range c.Waves {
				p := c.Policies[s.Name]
				fmt.Fprintf(out, "  wave %d  %-14s step=%s on_error=%s retries=%d\n", s.Wave, s.Name, p.StepID, p.OnError, p.Retries)
			}
			return nil
		},
	})
	return cmd
}
