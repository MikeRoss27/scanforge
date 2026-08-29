// Package app wires configuration, scope validation, orchestration and
// reporting together behind the CLI commands.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"

	"github.com/MikeRoss27/scanforge/internal/ascii"
	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/doctor"
	"github.com/MikeRoss27/scanforge/internal/initcmd"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/modules/attacksurface"
	"github.com/MikeRoss27/scanforge/internal/modules/dnsbrute"
	"github.com/MikeRoss27/scanforge/internal/modules/dnsx"
	"github.com/MikeRoss27/scanforge/internal/modules/ffuf"
	"github.com/MikeRoss27/scanforge/internal/modules/gau"
	"github.com/MikeRoss27/scanforge/internal/modules/httpcheck"
	"github.com/MikeRoss27/scanforge/internal/modules/httpx"
	"github.com/MikeRoss27/scanforge/internal/modules/jssecrets"
	"github.com/MikeRoss27/scanforge/internal/modules/jsverify"
	"github.com/MikeRoss27/scanforge/internal/modules/katana"
	"github.com/MikeRoss27/scanforge/internal/modules/naabu"
	"github.com/MikeRoss27/scanforge/internal/modules/nmap"
	"github.com/MikeRoss27/scanforge/internal/modules/nuclei"
	"github.com/MikeRoss27/scanforge/internal/modules/payloadgen"
	"github.com/MikeRoss27/scanforge/internal/modules/screenshot"
	"github.com/MikeRoss27/scanforge/internal/modules/subfinder"
	"github.com/MikeRoss27/scanforge/internal/modules/techcve"
	"github.com/MikeRoss27/scanforge/internal/modules/tlsx"
	"github.com/MikeRoss27/scanforge/internal/modules/wafw00f"
	"github.com/MikeRoss27/scanforge/internal/modules/whatweb"
	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	"github.com/MikeRoss27/scanforge/internal/report"
	"github.com/MikeRoss27/scanforge/internal/runner"
	"github.com/MikeRoss27/scanforge/internal/storage"
	"github.com/MikeRoss27/scanforge/internal/tui"
	"github.com/MikeRoss27/scanforge/internal/ui"
	"github.com/MikeRoss27/scanforge/internal/version"
)

type App struct {
	ConfigPath    string
	ScopePrompter ScopePrompter
	Wizard        WizardPrompter
}

func New(configPath string) *App {
	return &App{
		ConfigPath:    configPath,
		ScopePrompter: newTerminalScopePrompter(),
		Wizard:        newTerminalWizardPrompter(),
	}
}

type RunOptions struct {
	Target       string
	TargetsFile  string
	Profile      string
	Scope        string
	ScopeMode    string
	ScopeAdd     []string
	Exclusions   []string
	ConfirmScope bool
	DryRun       bool
	Verbose      bool

	// Proxy routes HTTP-capable modules through an intercepting proxy such
	// as Caido or Burp Suite (e.g. http://127.0.0.1:8080).
	Proxy string
	// Headers are applied to every outgoing HTTP request, for example to
	// carry an authenticated session (Cookie/Authorization).
	Headers []string
	// Nuclei carries nuclei-specific tuning (severity, tags, rate limiting).
	Nuclei modules.NucleiOptions
	// Ffuf carries ffuf-specific tuning (wordlist, status-code filtering).
	Ffuf modules.FfufOptions
	// NmapConcurrency bounds how many nmap processes run at once.
	NmapConcurrency int
}

type DoctorOptions struct {
	Profile string
	JSON    bool
	Verbose bool
}

type InitOptions struct {
	Force bool
}

// ExitCodeError carries a non-zero process exit code out of a command handler
// so the entry point can honor it without os.Exit in library code (which
// would skip defers and make the path untestable).
type ExitCodeError struct {
	Code int
}

func (e ExitCodeError) Error() string { return fmt.Sprintf("exit code %d", e.Code) }

func (a *App) loadConfig() (*config.Config, error) {
	return config.Load(config.ResolvePath(a.ConfigPath))
}

// runSession holds everything a single run needs after validation, so Run
// stays a thin sequence and each phase can be reasoned about and tested on
// its own.
type runSession struct {
	opts      RunOptions
	profile   string
	effective *effectiveScope
	scanRun   *storage.Run
	cfg       *config.Config
	reportErr error
}

// Run resolves the target(s) — one positional target or a --targets file —
// and executes the profile against each of them, keeping per-target runs and
// reports separated under runs/<target>/. A failing target does not abort
// the rest of the engagement.
func (a *App) Run(ctx context.Context, opts RunOptions) error {
	opts, err := a.applyWizard(opts)
	if err != nil {
		return err
	}
	targets, err := expandTargets(opts.Target, opts.TargetsFile)
	if err != nil {
		return err
	}
	var errs []error
	for _, target := range targets {
		one := opts
		one.Target = target
		if err := a.runOne(ctx, one); err != nil {
			errs = append(errs, fmt.Errorf("target %s: %w", target, err))
		}
	}
	return errors.Join(errs...)
}

func (a *App) runOne(ctx context.Context, opts RunOptions) error {
	session, err := a.prepareRun(opts)
	if err != nil {
		return err
	}

	results, runErr := session.execute(ctx)

	manifestErr := session.finalizeManifest(results, runErr)
	rep := session.generateReports()
	printRunSummaryBox(os.Stdout, session.scanRun, results, rep)
	printFindingsTable(rep)

	if !opts.DryRun {
		if err := notifyWebhook(ctx, session.cfg, session.scanRun, rep); err != nil {
			ui.Warn("Webhook notification failed: %v", err)
		}
	}

	// Best-effort report parse warnings (session.reportErr) are already
	// printed and must not fail the run: a truncated tool output should
	// never flip a valid scan's exit code for CI pipelines.
	return errors.Join(runErr, manifestErr)
}

// prepareRun loads the config, resolves the profile and effective scope, and
// creates the run directory with the effective scope persisted in the
// manifest.
func (a *App) prepareRun(opts RunOptions) (*runSession, error) {
	cfg, err := a.loadConfig()
	if err != nil {
		return nil, err
	}

	if opts.Target == "" {
		return nil, fmt.Errorf("target is required")
	}

	profile := opts.Profile
	if profile == "" {
		profile = cfg.DefaultProfile
	}

	effective, err := resolveScope(
		cfg,
		opts.Target,
		opts.Scope,
		opts.ScopeMode,
		opts.ScopeAdd,
		opts.Exclusions,
	)
	if err != nil {
		return nil, err
	}

	if _, err := cfg.ProfileModules(profile); err != nil {
		return nil, err
	}
	if effective.proposal.Source == scopeSourceImplicit {
		if err := a.confirmScope(effective.proposal, opts.ConfirmScope); err != nil {
			return nil, err
		}
	}

	store := storage.NewRunStore(config.WorkspaceDir(cfg))

	scanRun, err := store.Create(opts.Target)
	if err != nil {
		return nil, fmt.Errorf("failed to create run directory: %w", err)
	}
	scanRun.Manifest.Profile = profile
	effectiveScopePath := scanRun.Path("00_meta", "effective-scope.txt")
	if err := effective.value.WriteFile(effectiveScopePath); err != nil {
		return nil, fmt.Errorf("failed to persist effective scope: %w", err)
	}
	scanRun.Manifest.ScopePath = "00_meta/effective-scope.txt"
	scanRun.Manifest.ScopeSource = effective.proposal.Source
	scanRun.Manifest.ScopeMode = effective.proposal.Mode
	scanRun.Manifest.Outputs["effective_scope"] = scanRun.Manifest.ScopePath
	if err := scanRun.WriteManifest(); err != nil {
		return nil, fmt.Errorf("failed to record effective scope in manifest: %w", err)
	}

	return &runSession{
		opts:      opts,
		profile:   profile,
		effective: effective,
		scanRun:   scanRun,
		cfg:       cfg,
	}, nil
}

// execute builds the registry and executor, then runs the orchestrator in a
// goroutine while its events are consumed on the terminal. The returned error
// is the orchestrator-level failure; a TUI startup error aborts the run early.
func (s *runSession) execute(ctx context.Context) ([]*modules.Result, error) {
	var executor runner.Executor
	if s.opts.DryRun {
		executor = runner.NewDryRunExecutor(s.opts.Verbose)
	} else {
		executor = runner.NewRealExecutor(s.opts.Verbose)
	}

	ascii.PrintBanner()
	fmt.Println(ui.Dim("  by MikeRoss · v" + version.Version))
	fmt.Println()

	printRunInfoPanel(s.opts, s.profile, s.scanRun, *s.effective)

	orch := orchestrator.New(executor, buildRegistry(s.cfg))
	eventChan := make(chan orchestrator.Event)

	var results []*modules.Result
	var runErr error

	// runCtx is cancelled when the user quits the TUI early so the scan
	// actually stops instead of lingering in the background.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// done synchronizes the results assignment with the consumer below: the
	// event channel is closed by orchestrator.Run before it returns, so
	// waiting on the channel alone would still race with the write to
	// results/runErr.
	done := make(chan struct{})
	go func() {
		defer close(done)
		results, runErr = orch.Run(runCtx, s.scanRun, orchestrator.Options{
			Target:          s.opts.Target,
			Profile:         s.profile,
			Config:          s.cfg,
			DryRun:          s.opts.DryRun,
			Verbose:         s.opts.Verbose,
			Scope:           s.effective.value,
			Proxy:           s.opts.Proxy,
			Headers:         s.opts.Headers,
			Nuclei:          s.opts.Nuclei,
			Ffuf:            s.opts.Ffuf,
			NmapConcurrency: s.opts.NmapConcurrency,
		}, eventChan)
	}()

	if err := s.consumeEvents(cancel, eventChan, done); err != nil {
		// The TUI failed, but the orchestrator still ran: keep its results so
		// the manifest and reports reflect what actually happened.
		return results, errors.Join(runErr, err)
	}
	return results, runErr
}

// consumeEvents renders scan progress either through the Bubble Tea TUI (when
// the output is a terminal and the run is real) or as plain log lines, and
// returns once the orchestrator goroutine has finished. A non-nil error means
// the TUI itself failed and the scan was aborted.
func (s *runSession) consumeEvents(cancel context.CancelFunc, eventChan <-chan orchestrator.Event, done <-chan struct{}) error {
	if !s.opts.DryRun && term.IsTerminal(int(os.Stdout.Fd())) {
		model := tui.NewScanModel(eventChan, s.opts.Target, s.profile)
		p := tea.NewProgram(model, tea.WithAltScreen())
		finalModel, err := p.Run()
		if err != nil {
			cancel()
			drainEvents(eventChan)
			<-done
			return err
		}
		// Replay warnings collected in the scan view; once the TUI is gone
		// nothing else would surface them. The final model is the one that
		// actually received events during the run — the original model value
		// was copied when passed to the program.
		if scanModel, ok := finalModel.(tui.ScanModel); ok {
			for _, warning := range scanModel.Warnings() {
				ui.Warn("%s", warning)
			}
		}
		// The user may have quit the UI before the scan finished: cancel the
		// run and drain the remaining events so the orchestrator can return.
		cancel()
		drainEvents(eventChan)
		<-done
		return nil
	}
	for event := range eventChan {
		s.printEvent(event)
	}
	<-done
	return nil
}

// drainEvents discards remaining orchestrator events in the background so the
// orchestrator can unblock and return after the TUI has gone away.
func drainEvents(eventChan <-chan orchestrator.Event) {
	go func() {
		for range eventChan {
		}
	}()
}

func (s *runSession) printEvent(event orchestrator.Event) {
	switch e := event.(type) {
	case orchestrator.WaveStartEvent:
		fmt.Println(ui.WaveHeader(e.Wave, strings.Join(e.Modules, ", ")))
	case orchestrator.ModuleStartEvent:
		if s.opts.Verbose {
			ui.Info("Running module %q...", e.Name)
		}
	case orchestrator.ModuleDoneEvent:
		if s.opts.Verbose || !s.opts.DryRun {
			printModuleResult(os.Stdout, e)
		}
	case orchestrator.DeadlockEvent:
		ui.Warn("%s", e.Message)
	case orchestrator.WarningEvent:
		ui.Warn("%s", e.Message)
	case orchestrator.FindingEvent:
		printFinding(e)
	}
}

// printFinding renders a finding the moment a module reports it, e.g.
// "  [nuclei] CRITICAL exposed-git-config · https://example.com/.git/config",
// so long-running scanners like nuclei don't leave the operator staring at a
// blank terminal for the module's entire duration.
func printFinding(e orchestrator.FindingEvent) {
	severity := e.Severity
	if severity == "" {
		severity = "info"
	}
	line := ui.Dim("["+e.Module+"]") + " " + ui.Severity(strings.ToUpper(severity)) + " " + ui.Bold(e.Title)
	if e.Target != "" {
		line += ui.Secondary(" · " + e.Target)
	}
	fmt.Println("  " + line)
}

// printModuleResult renders a compact, aligned completion line for a module,
// e.g. "  ✓ subfinder      2.1s · 8 subdomains". Skipped and aborted modules
// get their own mark and an explicit status: a module that never ran must
// never render like one that succeeded.
func printModuleResult(out io.Writer, e orchestrator.ModuleDoneEvent) {
	mark := "✓"
	color := ui.Green
	switch {
	case e.Failed:
		mark = "✗"
		color = ui.Red
	case e.Status == "skipped":
		mark = "↓"
		color = ui.Yellow
	case e.Status == "aborted":
		mark = "◌"
		color = ui.Orange
	}
	name := color(ui.Bold(fmt.Sprintf("%-13s", e.Name)))

	var parts []string
	if e.Dur > 0 {
		parts = append(parts, ui.Dim(e.Dur.Round(time.Millisecond).String()))
	}
	switch {
	case e.Failed && e.Status != "" && e.Status != "failed":
		parts = append(parts, ui.Red(e.Status))
	case e.Failed:
		parts = append(parts, ui.Red("failed"))
	case e.Status == "skipped":
		parts = append(parts, ui.Dim("skipped (dependency missing)"))
	case e.Status == "aborted":
		parts = append(parts, ui.Orange("aborted"))
	case e.Summary != "":
		parts = append(parts, ui.Secondary(e.Summary))
	}

	line := fmt.Sprintf("  %s %s", color(mark), name)
	if len(parts) > 0 {
		line += " " + strings.Join(parts, " · ")
	}
	_, _ = fmt.Fprintln(out, line)
}

// finalizeManifest records completion time, per-module results and the run
// status (completed/partial/failed) in the run manifest.
func (s *runSession) finalizeManifest(results []*modules.Result, runErr error) error {
	s.scanRun.Manifest.CompletedAt = time.Now().Format(time.RFC3339)
	completedModules := 0
	for _, result := range results {
		if result.Status == "completed" {
			completedModules++
		}
	}
	// A user-initiated abort is recorded as such, not as a failure.
	if errors.Is(runErr, orchestrator.ErrRunAborted) {
		s.scanRun.Manifest.Status = "aborted"
	} else {
		switch {
		case runErr == nil && completedModules == len(results):
			s.scanRun.Manifest.Status = "completed"
		case completedModules == 0:
			s.scanRun.Manifest.Status = "failed"
		default:
			s.scanRun.Manifest.Status = "partial"
		}
	}

	for _, result := range results {
		s.scanRun.Manifest.Modules = append(s.scanRun.Manifest.Modules, storage.ModuleResult{
			Name:   result.Name,
			Status: result.Status,
		})
		for key, value := range result.OutputFiles {
			s.scanRun.Manifest.Outputs[key] = value
		}
	}

	return s.scanRun.WriteManifest()
}

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

func buildRegistry(cfg *config.Config) *modules.Registry {
	registry := modules.NewRegistry()
	registry.Register(subfinder.New(cfg.ToolPath("subfinder")))
	registry.Register(dnsbrute.New(cfg.ToolPath("shuffledns")))
	registry.Register(dnsx.New(cfg.ToolPath("dnsx")))
	registry.Register(httpx.New(cfg.ToolPath("httpx")))
	registry.Register(naabu.New(cfg.ToolPath("naabu")))
	registry.Register(nmap.New(cfg.ToolPath("nmap")))
	registry.Register(whatweb.New(cfg.ToolPath("whatweb")))
	registry.Register(wafw00f.New(cfg.ToolPath("wafw00f")))
	registry.Register(katana.New(cfg.ToolPath("katana")))
	registry.Register(jssecrets.New())
	registry.Register(jsverify.New(cfg.ToolPath("chromium")))
	registry.Register(attacksurface.New())
	registry.Register(ffuf.New(cfg.ToolPath("ffuf")))
	registry.Register(nuclei.New(cfg.ToolPath("nuclei")))
	registry.Register(gau.New(cfg.ToolPath("gau")))
	registry.Register(tlsx.New(cfg.ToolPath("tlsx")))
	registry.Register(techcve.New())
	registry.Register(httpcheck.New())
	registry.Register(payloadgen.New())
	registry.Register(screenshot.New(cfg.ToolPath("httpx")))
	return registry
}

func (a *App) Doctor(ctx context.Context, opts DoctorOptions) error {
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}

	runner := doctor.New(nil)
	checks, exitCode, err := runner.Run(ctx, doctor.Options{
		Profile: opts.Profile,
		JSON:    opts.JSON,
		Verbose: opts.Verbose,
		Config:  cfg,
	})
	if err != nil {
		return err
	}

	if opts.JSON {
		output, err := doctor.FormatChecksJSON(checks)
		if err != nil {
			return err
		}
		fmt.Println(output)
	} else {
		fmt.Println(ui.Bold(ui.Primary("ScanForge Doctor v" + version.Version)))
		fmt.Println()
		fmt.Print(doctor.FormatChecks(checks))
	}

	if exitCode != 0 {
		return ExitCodeError{Code: exitCode}
	}

	return nil
}

func (a *App) Init(ctx context.Context, opts InitOptions) error {
	result, err := initcmd.Run(initcmd.Options{Force: opts.Force})
	if err != nil {
		for _, path := range result.Created {
			ui.Success("Created: %s", path)
		}
		for _, path := range result.Skipped {
			ui.Info("Skipped: %s", path)
		}
		return err
	}

	for _, path := range result.Created {
		ui.Success("Created: %s", path)
	}
	for _, path := range result.Skipped {
		ui.Info("Skipped: %s", path)
	}

	fmt.Println()
	fmt.Println(ui.Header("Initialization Complete", ui.AccentGreen))

	ui.Info("Next steps:")
	fmt.Printf("  %s %s\n", ui.Primary("1."), ui.Bold("scanforge doctor"))
	fmt.Printf("  %s %s\n", ui.Primary("2."), ui.Bold("scanforge plan example.com"))
	fmt.Printf("  %s %s\n", ui.Primary("3."), ui.Bold("scanforge run example.com --dry-run"))
	fmt.Printf("  %s %s\n", ui.Primary("4."), ui.Bold("scanforge run example.com"))

	return nil
}
