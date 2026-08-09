package app

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/report"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

// ExportFormat selects the machine-readable output format.
type ExportFormat string

const (
	ExportSARIF      ExportFormat = "sarif"
	ExportDefectDojo ExportFormat = "defectdojo"
)

// ExportOptions selects the run and format to export.
type ExportOptions struct {
	// Run is a run root directory (runs/<target>/<id>).
	Run string
	// Format is one of ExportSARIF or ExportDefectDojo.
	Format ExportFormat
	// Out overrides the default output path (empty = report.<ext> in the run dir).
	Out string
}

// Export reconsolidates a run's report and serializes it in the requested
// machine-readable format. It returns the path of the written file.
func (a *App) Export(ctx context.Context, opts ExportOptions) (string, error) {
	run, err := storage.OpenRun(opts.Run)
	if err != nil {
		return "", err
	}
	rep, err := report.GenerateReport(opts.Run, &run.Manifest)
	if err != nil {
		return "", fmt.Errorf("generate report for %s: %w", opts.Run, err)
	}

	out := opts.Out
	if out == "" {
		switch opts.Format {
		case ExportSARIF:
			out = filepath.Join(run.RootDir, "report.sarif")
		case ExportDefectDojo:
			out = filepath.Join(run.RootDir, "report.defectdojo.json")
		default:
			return "", fmt.Errorf("unsupported export format %q (use %q or %q)", opts.Format, ExportSARIF, ExportDefectDojo)
		}
	}

	switch opts.Format {
	case ExportSARIF:
		err = rep.WriteSARIF(out)
	case ExportDefectDojo:
		err = rep.WriteDefectDojo(out)
	default:
		return "", fmt.Errorf("unsupported export format %q (use %q or %q)", opts.Format, ExportSARIF, ExportDefectDojo)
	}
	if err != nil {
		return "", err
	}
	return out, nil
}

// ParseExportFormat normalizes a user-supplied format name.
func ParseExportFormat(value string) (ExportFormat, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(ExportSARIF):
		return ExportSARIF, nil
	case string(ExportDefectDojo):
		return ExportDefectDojo, nil
	default:
		return "", fmt.Errorf("unknown format %q (use %q or %q)", value, ExportSARIF, ExportDefectDojo)
	}
}
