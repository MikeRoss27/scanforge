package app

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/ascii"
	"github.com/MikeRoss27/scanforge/internal/console"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/report"
	"github.com/MikeRoss27/scanforge/internal/scope"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

// generateReports renders report.json and report.md from the raw artifacts
// and announces it on the console. Failures are downgraded to warnings so a
// scan always ends with the summary block.
func (s *runSession) generateReports() *report.Report {
	if s.opts.Verbosity <= console.Quiet {
		s.console.Blank()
	} else {
		s.console.Info("generating report")
	}

	rep, err := report.GenerateReport(s.scanRun.RootDir, &s.scanRun.Manifest)
	if err != nil {
		s.console.Warn("failed to generate report: %v", err)
		s.reportErr = err
		return rep
	}

	jsonPath := filepath.Join(s.scanRun.RootDir, "report.json")
	mdPath := filepath.Join(s.scanRun.RootDir, "report.md")
	if err := errors.Join(rep.WriteJSON(jsonPath), rep.WriteMarkdown(mdPath)); err != nil {
		s.console.Warn("failed to write report: %v", err)
		s.reportErr = err
	}
	return rep
}

// printIntro renders the banner and the compact run configuration header,
// then the first informational lines of the run.
func (s *runSession) printIntro(moduleCount int) {
	if s.bannerEnabled() {
		if wordmark, tagline, ok := ascii.Banner(s.term.Width); ok {
			s.console.PrintBanner(wordmark, tagline)
		}
	}
	s.console.PrintHeader(console.RunHeader{
		Target:    s.opts.Target,
		Profile:   s.profile,
		Scope:     describeScope(s.effective.proposal),
		Modules:   moduleCount,
		Proxy:     s.opts.Proxy,
		Headers:   s.opts.Headers,
		DryRun:    s.opts.DryRun,
		OutputDir: displayPath(s.scanRun.RootDir),
	})
	if s.opts.Verbosity >= console.Normal {
		s.console.Info("scope validated (%s)", s.scopeSummary(s.effective.proposal))
		if moduleCount > 0 {
			s.console.Info("preparing pipeline with %d modules", moduleCount)
		}
		s.console.Blank()
	}
}

// bannerEnabled decides whether the wordmark is printed: an explicit
// SCANFORGE_BANNER wins, otherwise it shows on interactive terminals only
// and never in quiet mode.
func (s *runSession) bannerEnabled() bool {
	switch ascii.ResolveBannerSetting() {
	case ascii.BannerOff:
		return false
	case ascii.BannerOn:
		return true
	default:
		return s.term.Tty && s.opts.Verbosity > console.Quiet
	}
}

// displayPath renders a path relative to the working directory when
// possible, so run locations stay short and copy/paste friendly.
func displayPath(path string) string {
	if rel, err := filepath.Rel(".", path); err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return path
}

// describeScope turns the effective scope proposal into one honest line.
func describeScope(proposal ScopeProposal) string {
	switch {
	case proposal.Source == scopeSourceImplicit && proposal.Mode == string(scope.ModeDomain):
		return "domain + subdomains"
	case proposal.Source == scopeSourceImplicit:
		return "exact target only"
	default:
		entries := "entries"
		if len(proposal.Entries) == 1 {
			entries = "entry"
		}
		return fmt.Sprintf("%s · %d %s", proposal.Input, len(proposal.Entries), entries)
	}
}

// scopeSummary is the short scope note used on the [INF] validation line.
// It reads like the header's Scope row; the long reason note (e.g. why the
// configured file did not allow the target) is only shown at -v so the
// default line stays a single glance.
func (s *runSession) scopeSummary(proposal ScopeProposal) string {
	base := describeScope(proposal)
	if proposal.Source == scopeSourceImplicit {
		base += " · implicit"
	}
	if s.opts.Verbosity >= console.Verbose && proposal.Note != "" {
		return base + " · " + proposal.Note
	}
	return base
}

// buildSummary projects the finished run into the console summary: only
// facts that actually exist, no invented metrics.
func buildSummary(scanRun *storage.Run, results []*modules.Result, rep *report.Report, triageConfigured bool) console.Summary {
	manifest := scanRun.Manifest
	summary := console.Summary{
		Target:     manifest.Target,
		Status:     manifest.Status,
		RunDir:     displayPath(scanRun.RootDir),
		ReportJSON: displayPath(filepath.Join(scanRun.RootDir, "report.json")),
		ReportMD:   displayPath(filepath.Join(scanRun.RootDir, "report.md")),
		TriageHint: triageConfigured,
	}
	// Active time only: a resumed run must not count the idle gap between
	// the interruption and the resume.
	summary.Duration = manifest.ActiveDuration()

	summary.Modules = len(results)
	for _, res := range results {
		switch {
		case res.Status == "completed":
			summary.Completed++
		case modules.IsNotApplicable(res):
			// Nothing to do for this target (e.g. no WordPress): already
			// shown as [SKIP] live; listing it under SKIPPED is noise.
			summary.NotApplicable++
		case res.Status == "skipped", res.Status == "aborted":
			// Never ran to completion, but not a failure either: listing
			// these under FAILED would overstate what went wrong.
			summary.Skipped = append(summary.Skipped, fmt.Sprintf("%s (%s)", res.Name, res.Status))
		default:
			summary.Failed = append(summary.Failed, fmt.Sprintf("%s (%s)", res.Name, res.Status))
		}
	}

	if rep != nil {
		var assets, alive, urls, ports int
		techs := map[string]bool{}
		for _, asset := range rep.Assets {
			assets++
			alive += len(asset.HTTP)
			urls += len(asset.Paths)
			ports += len(asset.Ports)
			for _, t := range asset.Technologies {
				techs[t] = true
			}
		}
		summary.Assets, summary.Alive, summary.URLs, summary.Ports = assets, alive, urls, ports
		summary.Techs = topTechs(techs)
		summary.Findings = countBySeverity(rep)
		for _, n := range summary.Findings {
			summary.Total += n
		}
		summary.FindingTypes = findingTypesByReport(rep)
	}
	return summary
}

// findingTypesByReport groups every vulnerability in the report by
// (module, title, severity) so the closing summary's "Finding types" recap
// reflects the same authoritative data as the severity counts above it,
// instead of the live event stream — which can miss findings a module
// reports only once report generation parses its raw output (e.g. secrets
// deduplicated differently than the live stream saw them).
func findingTypesByReport(rep *report.Report) []console.FindingType {
	type key struct{ module, title, severity string }
	counts := make(map[key]int)
	for _, asset := range rep.Assets {
		for _, vuln := range asset.Vulnerabilities {
			title := vuln.Title
			if title == "" {
				title = vuln.TemplateID
			}
			counts[key{module: vuln.Source, title: title, severity: strings.ToLower(vuln.Severity)}]++
		}
	}
	types := make([]console.FindingType, 0, len(counts))
	for k, n := range counts {
		types = append(types, console.FindingType{Module: k.module, Title: k.title, Severity: k.severity, Count: n})
	}
	return types
}

// topTechs returns the sorted technology names, capped so one wide terminal
// line cannot turn into a wall of tags.
func topTechs(techs map[string]bool) []string {
	names := make([]string, 0, len(techs))
	for t := range techs {
		names = append(names, t)
	}
	sort.Strings(names)
	const maxTechs = 4
	if len(names) > maxTechs {
		names = append(names[:maxTechs], "…")
	}
	return names
}

// countBySeverity counts the report's vulnerabilities per canonical
// severity level.
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
