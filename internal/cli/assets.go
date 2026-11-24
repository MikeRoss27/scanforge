package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/MikeRoss27/scanforge/internal/assets"
	"github.com/spf13/cobra"
)

// NewAssetsCommand lists the per-target asset history written after every
// completed run (runs/<target>/assets.jsonl).
func NewAssetsCommand(application *app.App) *cobra.Command {
	var onlyNew, onlyGone, jsonOut bool
	cmd := &cobra.Command{
		Use:     "assets <target>",
		GroupID: groupReports,
		Short:   "Inspect the asset history of a target (new, unchanged, changed, gone)",
		Long: "Lists the current state of every asset recorded in runs/<target>/assets.jsonl " +
			"(subdomains, URLs, paths, ports, technologies, findings). The history is " +
			"appended after each completed run and drives 'scanforge run --incremental'.",
		Example: `  scanforge assets example.com
  scanforge assets example.com --new
  scanforge assets example.com --gone --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			recs, err := application.Assets(app.AssetsOptions{Target: args[0], New: onlyNew, Gone: onlyGone})
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if jsonOut {
				if recs == nil {
					recs = []assets.Record{}
				}
				data, err := json.MarshalIndent(recs, "", "  ")
				if err != nil {
					return err
				}
				_, err = fmt.Fprintln(out, string(data))
				return err
			}
			_, err = fmt.Fprint(out, FormatAssets(recs))
			return err
		},
	}
	cmd.Flags().BoolVar(&onlyNew, "new", false, "Only assets whose current status is new")
	cmd.Flags().BoolVar(&onlyGone, "gone", false, "Only assets that disappeared")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit the records as JSON")
	return cmd
}

// FormatAssets renders asset records as an aligned table.
func FormatAssets(recs []assets.Record) string {
	if len(recs) == 0 {
		return "no matching assets\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%-10s %-10s %-22s %-22s %s\n", "STATUS", "TYPE", "FIRST SEEN", "LAST RUN", "VALUE")
	for _, r := range recs {
		fmt.Fprintf(&b, "%-10s %-10s %-22s %-22s %s\n", r.Status, r.Type, r.FirstSeen, r.LastRunID, r.Value)
	}
	return b.String()
}
