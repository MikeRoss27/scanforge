package cli

import (
	"encoding/json"
	"fmt"

	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/MikeRoss27/scanforge/internal/console"
	"github.com/spf13/cobra"
)

func NewResumeCommand(application *app.App) *cobra.Command {
	var verbosityCount int
	var quiet bool
	var proxy string
	var headers []string
	cmd := &cobra.Command{
		Use:     "resume <run-id>",
		GroupID: groupCore,
		Short:   "Resume an interrupted run from its checkpoints",
		Long: "Reloads a run directory, re-validates the module graph and re-executes " +
			"only the modules that did not complete or whose inputs changed. The stored " +
			"effective scope is reused as is and can never be widened. --proxy and " +
			"--header are not stored in the manifest: pass them again for an " +
			"authenticated run, otherwise the affected modules are re-executed.",
		Example: `  scanforge resume 2026-08-18_10-00-00
  scanforge resume example.com/2026-08-18_10-00-00`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return application.Resume(cmd.Context(), app.ResumeOptions{
				Run:       args[0],
				Verbosity: console.ParseVerbosity(verbosityCount, quiet),
				Proxy:     proxy,
				Headers:   headers,
			})
		},
	}
	cmd.Flags().CountVarP(&verbosityCount, "verbose", "v", "Increase verbosity")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Only findings, warnings, errors and the summary")
	cmd.Flags().StringVar(&proxy, "proxy", "", "Proxy used by the original run (not stored, part of the input hash)")
	cmd.Flags().StringArrayVarP(&headers, "header", "H", nil, "Header used by the original run (not stored, part of the input hash)")
	return cmd
}

func NewStatusCommand(application *app.App) *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:     "status <run-id>",
		GroupID: groupReports,
		Short:   "Show the checkpoint state of a run",
		Long: `Prints each module's status (pending, running, completed, failed, skipped,
cancelled), its input hash and the run's scope provenance. <run-id> can be a
bare id, <target>/<id> or a run directory path.`,
		Example: `  scanforge status 2026-08-18_10-00-00
  scanforge status example.com/2026-08-18_10-00-00 --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			run, text, err := application.RunStatus(args[0])
			if err != nil {
				return err
			}
			if jsonOut {
				data, err := json.MarshalIndent(run.Manifest, "", "  ")
				if err != nil {
					return err
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), string(data))
				return err
			}
			_, err = fmt.Fprint(cmd.OutOrStdout(), text)
			return err
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit the manifest as JSON")
	return cmd
}

func NewRunsCommand(application *app.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "runs",
		GroupID: groupReports,
		Short:   "Inspect previous runs",
		Long:    "Lists and inspects runs stored in the workspace's runs/ directory.",
		Example: `  scanforge runs list
  scanforge runs list --target example.com --json`,
	}
	var target string
	var jsonOut bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List runs in the workspace, newest first",
		Example: `  scanforge runs list
  scanforge runs list --target example.com --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			runs, err := application.ListRuns(target)
			if err != nil {
				return err
			}
			if jsonOut {
				type row struct {
					ID      string `json:"id"`
					Target  string `json:"target"`
					Status  string `json:"status"`
					Profile string `json:"profile"`
					Started string `json:"started_at"`
					Dir     string `json:"dir"`
				}
				rows := make([]row, 0, len(runs))
				for _, r := range runs {
					rows = append(rows, row{r.ID, r.Target, r.Manifest.Status, r.Manifest.Profile, r.Manifest.StartedAt, r.RootDir})
				}
				data, err := json.MarshalIndent(rows, "", "  ")
				if err != nil {
					return err
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), string(data))
				return err
			}
			_, err = fmt.Fprint(cmd.OutOrStdout(), app.FormatRunList(runs))
			return err
		},
	}
	list.Flags().StringVar(&target, "target", "", "Only list runs of this target")
	list.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON")
	cmd.AddCommand(list)
	return cmd
}
