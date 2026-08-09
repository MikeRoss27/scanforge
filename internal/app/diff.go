package app

import (
	"context"
	"fmt"

	"github.com/MikeRoss27/scanforge/internal/report"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

// DiffOptions selects the two runs to compare.
type DiffOptions struct {
	// Run1 and Run2 are run root directories (runs/<target>/<id>).
	Run1 string
	Run2 string
}

// Diff loads two runs, regenerates their consolidated reports from the raw
// artifacts and computes the delta between them. The returned string is the
// human-readable rendering; the delta itself is also returned so callers can
// emit JSON for CI.
func (a *App) Diff(ctx context.Context, opts DiffOptions) (*report.RunDelta, string, error) {
	before, err := storage.OpenRun(opts.Run1)
	if err != nil {
		return nil, "", fmt.Errorf("open first run: %w", err)
	}
	after, err := storage.OpenRun(opts.Run2)
	if err != nil {
		return nil, "", fmt.Errorf("open second run: %w", err)
	}
	if before.Target != after.Target {
		return nil, "", fmt.Errorf("runs target different assets (%q vs %q), diff requires the same target", before.Target, after.Target)
	}

	reportBefore, err := report.GenerateReport(opts.Run1, &before.Manifest)
	if err != nil {
		return nil, "", fmt.Errorf("generate report for %s: %w", opts.Run1, err)
	}
	reportAfter, err := report.GenerateReport(opts.Run2, &after.Manifest)
	if err != nil {
		return nil, "", fmt.Errorf("generate report for %s: %w", opts.Run2, err)
	}

	delta := report.CompareReports(reportBefore, reportAfter)
	return &delta, report.FormatRunDelta(delta), nil
}
