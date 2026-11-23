package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/MikeRoss27/scanforge/internal/benchmark"
	"github.com/MikeRoss27/scanforge/internal/console"
	"github.com/MikeRoss27/scanforge/internal/ui"
	"github.com/spf13/cobra"
)

// NewBenchmarkCommand builds "scanforge benchmark": a maintainer tool, not
// part of an authorized client engagement. It runs ScanForge's real
// pipeline against known, intentionally-vulnerable lab targets — Google's
// Firing Range, Acunetix's testphp.vulnweb.com, OWASP Juice Shop's public
// demo, and a locally self-hosted DVWA — and scores the result, so a
// regression in detection or in the pipeline itself shows up as a failing
// benchmark instead of silently shipping. It is explicitly also meant to be
// run by an AI agent: --json gives a stable, machine-parseable result and
// the process exit code reflects pass/fail.
func NewBenchmarkCommand(application *app.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "benchmark",
		GroupID: groupMaintenance,
		Short:   "Benchmark the scan pipeline against known vulnerable lab targets (maintainer tool)",
		Long: `For ScanForge contributors (human or AI): runs the real scan pipeline
against bundled, intentionally-vulnerable lab targets and scores the
result against documented expectations, to catch pipeline or detection
regressions. This is NOT part of an authorized client engagement — it
hits Google's Firing Range and Acunetix's testphp.vulnweb.com directly
(both are built for exactly this), and OWASP Juice Shop's SHARED public
demo (be considerate of load; see "scanforge benchmark list" for a
self-hosted alternative). DVWA requires a local Docker container you
start yourself.`,
		Example: `  scanforge benchmark list
  scanforge benchmark run firing-range
  scanforge benchmark run dvwa --target http://localhost:4280
  scanforge benchmark run --all --json`,
	}
	cmd.AddCommand(newBenchmarkListCommand())
	cmd.AddCommand(newBenchmarkRunCommand(application))
	return cmd
}

func newBenchmarkListCommand() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the bundled benchmark labs",
		RunE: func(cmd *cobra.Command, args []string) error {
			labs, err := benchmark.Labs()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if jsonOut {
				data, err := json.MarshalIndent(labs, "", "  ")
				if err != nil {
					return err
				}
				_, err = fmt.Fprintln(out, string(data))
				return err
			}
			var rows [][]string
			for _, lab := range labs {
				strict := "advisory"
				if lab.Strict {
					strict = "strict"
				}
				rows = append(rows, []string{lab.Name, lab.Target, strict, lab.Description})
			}
			_, err = fmt.Fprintln(out, ui.Table([]string{"LAB", "TARGET", "MODE", "DESCRIPTION"}, rows))
			return err
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output the lab list as JSON")
	return cmd
}

func newBenchmarkRunCommand(application *app.App) *cobra.Command {
	var jsonOut bool
	var all bool
	var target string
	var timeout time.Duration
	var verbose bool
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "run [lab]",
		Short: "Run the pipeline against one (or every) bundled lab and score the result",
		Long: `Runs ScanForge's real scan pipeline against the named lab (see
"scanforge benchmark list"), then scores the resulting report against
that lab's documented expectations. Exits 0 only when every requested
lab passed; a lab whose target is unreachable fails fast with its setup
instructions instead of running the full pipeline.`,
		Example: `  scanforge benchmark run firing-range
  scanforge benchmark run testphp-vulnweb --json
  scanforge benchmark run dvwa --target http://localhost:4280
  scanforge benchmark run --all`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var lab string
			if len(args) > 0 {
				lab = args[0]
			}
			if all && lab != "" {
				return fmt.Errorf("--all does not take a lab argument (got %q)", lab)
			}
			if !all && lab == "" {
				return fmt.Errorf("give a lab name (see %q) or pass --all", "scanforge benchmark list")
			}
			if all && target != "" {
				return fmt.Errorf("--target only applies to a single lab, not --all")
			}

			verbosity := console.Quiet
			if verbose {
				verbosity = console.Normal
			}

			ctx := cmd.Context()
			out := cmd.OutOrStdout()

			var scores []benchmark.Score
			if all {
				var err error
				scores, err = application.BenchmarkAll(ctx, app.BenchmarkAllOptions{
					Timeout:   timeout,
					Verbosity: verbosity,
					DryRun:    dryRun,
				})
				if err != nil {
					return err
				}
			} else {
				score, err := application.Benchmark(ctx, app.BenchmarkOptions{
					Lab:       lab,
					Target:    target,
					Timeout:   timeout,
					Verbosity: verbosity,
					DryRun:    dryRun,
				})
				if err != nil {
					return err
				}
				scores = []benchmark.Score{score}
			}

			if jsonOut {
				if err := printScoresJSON(out, scores, all); err != nil {
					return err
				}
			} else {
				printScoresHuman(out, scores)
			}

			if !allPassed(scores) {
				return app.ExitCodeError{Code: 1}
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output the score(s) as JSON")
	cmd.Flags().BoolVar(&all, "all", false, "Run every bundled lab, sequentially")
	cmd.Flags().StringVar(&target, "target", "", "Override the lab's default target (single-lab only), e.g. a self-hosted DVWA on a different port")
	cmd.Flags().DurationVar(&timeout, "timeout", 0, "Override the lab's own pipeline timeout")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show the full scan output instead of just the score")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Skip the reachability check and run the pipeline in dry-run mode (sanity-check the wiring without touching the network)")

	return cmd
}

func allPassed(scores []benchmark.Score) bool {
	for _, score := range scores {
		if !score.OverallPass {
			return false
		}
	}
	return len(scores) > 0
}

func printScoresJSON(out io.Writer, scores []benchmark.Score, all bool) error {
	var payload any = scores
	if !all {
		// A single lab run emits one object, not a one-element array, so
		// a caller doesn't need to special-case array-of-one.
		if len(scores) != 1 {
			return fmt.Errorf("internal error: expected exactly one score, got %d", len(scores))
		}
		payload = scores[0]
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(data))
	return err
}

func printScoresHuman(out io.Writer, scores []benchmark.Score) {
	for _, score := range scores {
		printScoreHuman(out, score)
	}
	if len(scores) > 1 {
		var rows [][]string
		for _, score := range scores {
			rows = append(rows, []string{score.Lab, passLabel(score), strconv.Itoa(score.FindingsTotal), fmt.Sprintf("%.1fs", score.DurationSecs)})
		}
		_, _ = fmt.Fprintln(out, ui.Table([]string{"LAB", "RESULT", "FINDINGS", "DURATION"}, rows))
	}
}

func printScoreHuman(out io.Writer, score benchmark.Score) {
	header := fmt.Sprintf("%s — %s", ui.Bold(score.Lab), score.Target)
	_, _ = fmt.Fprintln(out, header)

	if score.Error != "" {
		_, _ = fmt.Fprintln(out, "  "+ui.Red(passLabel(score))+"  "+score.Error)
		_, _ = fmt.Fprintln(out)
		return
	}

	mode := "advisory"
	if score.Strict {
		mode = "strict"
	}
	_, _ = fmt.Fprintf(out, "  %s  (%s, %d findings, %.1fs)\n", passLabel(score), mode, score.FindingsTotal, score.DurationSecs)

	for _, cat := range score.Categories {
		symbol := ui.Green("ok")
		if !cat.Pass {
			symbol = ui.Yellow("miss")
		}
		_, _ = fmt.Fprintf(out, "    %-5s %-20s found=%d min=%d\n", symbol, cat.Name, cat.Found, cat.MinCount)
	}
	for _, tech := range score.Technologies {
		symbol := ui.Green("ok")
		if !tech.Found {
			symbol = ui.Dim("miss")
		}
		_, _ = fmt.Fprintf(out, "    %-5s tech: %s\n", symbol, tech.Want)
	}
	_, _ = fmt.Fprintln(out)
}

func passLabel(score benchmark.Score) string {
	if score.Error != "" {
		return ui.Red("ERROR")
	}
	if score.OverallPass {
		return ui.Green("PASS")
	}
	return ui.Red("FAIL")
}
