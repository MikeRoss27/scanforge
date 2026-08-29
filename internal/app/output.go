package app

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/report"
	"github.com/MikeRoss27/scanforge/internal/storage"
	"github.com/MikeRoss27/scanforge/internal/ui"
)

// generateReports renders report.json and report.md from the raw artifacts
// and prints the terminal summary. Failures are downgraded to warnings so a
// scan always ends with the summary box.
func (s *runSession) generateReports() *report.Report {
	fmt.Println()
	ui.Info("Generating report...")

	rep, err := report.GenerateReport(s.scanRun.RootDir, &s.scanRun.Manifest)
	if err != nil {
		ui.Warn("Failed to generate report: %v", err)
		s.reportErr = err
		return rep
	}

	jsonPath := filepath.Join(s.scanRun.RootDir, "report.json")
	mdPath := filepath.Join(s.scanRun.RootDir, "report.md")
	if err := errors.Join(rep.WriteJSON(jsonPath), rep.WriteMarkdown(mdPath)); err != nil {
		ui.Warn("Failed to write report: %v", err)
		s.reportErr = err
	}
	return rep
}

// printRunInfoPanel renders a sleek bordered panel with the run configuration
// instead of the old full-width cyan block.
func printRunInfoPanel(opts RunOptions, profile string, scanRun *storage.Run, effective effectiveScope) {
	kv := func(key, val string) string {
		return fmt.Sprintf("%-9s %s", ui.DimBold(key), val)
	}

	dryTag := ui.Green("OFF")
	if opts.DryRun {
		dryTag = ui.Yellow("ON")
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", kv("TARGET", ui.AccentBold(opts.Target)))
	fmt.Fprintf(&b, "%s\n", kv("PROFILE", ui.Primary(profile)))
	fmt.Fprintf(&b, "%s\n", kv("SCOPE", ui.Dim(fmt.Sprintf("%s (%s, mode %s)", scanRun.Manifest.ScopePath, effective.proposal.Source, effective.proposal.Mode))))
	fmt.Fprintf(&b, "%s\n", kv("DRY RUN", dryTag))
	fmt.Fprintf(&b, "%s", kv("OUTPUT", ui.Dim(scanRun.RootDir)))

	fmt.Println(ui.PanelWith("⚡ RUN STARTED", b.String(), ui.Accent, ui.Accent))
	fmt.Println()
}

// printRunSummaryBox renders a single, hard-to-miss closing panel. Unlike
// the mid-scroll module log and report.PrintTerminalSummary (which only
// prints when report generation succeeds), this always renders so a run
// never ends in just one easy-to-miss text line.
func printRunSummaryBox(out io.Writer, scanRun *storage.Run, results []*modules.Result, rep *report.Report) {
	duration := "unknown"
	if started, err := time.Parse(time.RFC3339, scanRun.Manifest.StartedAt); err == nil {
		if completed, err := time.Parse(time.RFC3339, scanRun.Manifest.CompletedAt); err == nil {
			duration = completed.Sub(started).Round(time.Second).String()
		}
	}

	completedCount := 0
	var failedModules, skippedModules []string
	for _, res := range results {
		switch res.Status {
		case "completed":
			completedCount++
		case "skipped", "aborted":
			// Never ran to completion, but not a failure either: listing
			// these under FAILED would overstate what went wrong.
			skippedModules = append(skippedModules, fmt.Sprintf("%s (%s)", res.Name, res.Status))
		default:
			failedModules = append(failedModules, fmt.Sprintf("%s (%s)", res.Name, res.Status))
		}
	}

	kv := func(key, val string) string {
		return fmt.Sprintf("%-9s %s", ui.DimBold(key), val)
	}

	border := ui.Accent
	switch scanRun.Manifest.Status {
	case "completed":
		border = ui.AccentGreen
	case "partial":
		border = ui.AccentYellow
	case "failed":
		border = ui.AccentRed
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", statusLine(scanRun.Manifest.Status))
	fmt.Fprintf(&b, "%s\n", kv("DURATION", ui.Dim(duration)))
	fmt.Fprintf(&b, "%s\n", kv("MODULES", ui.ProgressBar(completedCount, len(results), 20)))
	if stats := formatRunStats(rep); stats != "" {
		fmt.Fprintf(&b, "%s\n", kv("STATS", stats))
	}
	fmt.Fprintf(&b, "%s\n", kv("FINDINGS", formatSeverityCounts(countBySeverity(rep))))
	if len(failedModules) > 0 {
		fmt.Fprintf(&b, "%s\n", kv("FAILED", ui.Red(wrapModuleList(failedModules))))
	}
	if len(skippedModules) > 0 {
		fmt.Fprintf(&b, "%s\n", kv("SKIPPED", ui.Yellow(wrapModuleList(skippedModules))))
	}
	fmt.Fprintf(&b, "%s", kv("OUTPUT", ui.Dim(scanRun.RootDir)))

	_, _ = fmt.Fprintln(out, ui.PanelWith("🏁 SCAN SUMMARY", b.String(), border, border))
}

// wrapModuleList renders "name (status)" entries on lines of at most
// ~maxListWidth characters so a long skip list cannot stretch the summary
// panel past the terminal width; continuation lines align under the kv value
// column. Widths are approximated from the plain names (module names and
// statuses are ASCII), which stays on the safe side once ANSI colors are
// layered on.
func wrapModuleList(items []string) string {
	const maxListWidth = 66
	indent := strings.Repeat(" ", 10) // value column of the "%-9s " kv layout

	var lines []string
	current := ""
	for _, item := range items {
		if current == "" {
			current = item
			continue
		}
		if len(current)+len(", ")+len(item) > maxListWidth {
			lines = append(lines, current)
			current = item
			continue
		}
		current += ", " + item
	}
	if current != "" {
		lines = append(lines, current)
	}
	return strings.Join(lines, "\n"+indent)
}

// printFindingsTable renders the severity-sorted findings table below the
// summary box when the run produced any vulnerabilities.
func printFindingsTable(rep *report.Report) {
	if table := report.FormatFindingsTable(rep); table != "" {
		fmt.Println()
		fmt.Println(table)
	}
}

// formatRunStats builds a compact one-line inventory of what the scan found,
// e.g. "3 assets · 5 ports · 12 paths · nginx, React". Returns an empty
// string when nothing was discovered so the summary box stays clean.
func formatRunStats(rep *report.Report) string {
	if rep == nil {
		return ""
	}

	var assets, ports, paths int
	techSet := make(map[string]bool)
	for _, asset := range rep.Assets {
		assets++
		ports += len(asset.Ports)
		paths += len(asset.Paths)
		for _, t := range asset.Technologies {
			techSet[t] = true
		}
	}

	var parts []string
	if assets > 0 {
		parts = append(parts, fmt.Sprintf("%d asset(s)", assets))
	}
	if ports > 0 {
		parts = append(parts, fmt.Sprintf("%d port(s)", ports))
	}
	if paths > 0 {
		parts = append(parts, fmt.Sprintf("%d path(s)", paths))
	}

	techs := make([]string, 0, len(techSet))
	for t := range techSet {
		techs = append(techs, t)
	}
	sort.Strings(techs)
	if len(techs) > 0 {
		const maxTechs = 4
		if len(techs) > maxTechs {
			techs = append(techs[:maxTechs], "…")
		}
		parts = append(parts, ui.Secondary(strings.Join(techs, ", ")))
	}

	return strings.Join(parts, " · ")
}

func statusLine(status string) string {
	switch status {
	case "completed":
		return ui.Green(ui.Bold("✓ COMPLETED"))
	case "partial":
		return ui.Yellow(ui.Bold("◐ PARTIAL"))
	case "failed":
		return ui.Red(ui.Bold("✗ FAILED"))
	default:
		return ui.DimBold(strings.ToUpper(status))
	}
}

func countBySeverity(rep *report.Report) map[string]int {
	counts := make(map[string]int)
	if rep == nil {
		return counts
	}
	for _, asset := range rep.Assets {
		for _, vuln := range asset.Vulnerabilities {
			counts[strings.ToLower(vuln.Severity)]++
		}
	}
	return counts
}

func formatSeverityCounts(counts map[string]int) string {
	levels := []string{"critical", "high", "medium", "low", "info"}

	var parts []string
	total := 0
	for _, key := range levels {
		if n := counts[key]; n > 0 {
			parts = append(parts, ui.Severity(fmt.Sprintf("%d %s", n, key)))
			total += n
		}
	}
	if total == 0 {
		return ui.Green("none")
	}
	return strings.Join(parts, ", ")
}
