package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"

	"github.com/MikeRoss27/scanforge/internal/ascii"
	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/doctor"
	"github.com/MikeRoss27/scanforge/internal/initcmd"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/modules/dnsx"
	"github.com/MikeRoss27/scanforge/internal/modules/ffuf"
	"github.com/MikeRoss27/scanforge/internal/modules/gau"
	"github.com/MikeRoss27/scanforge/internal/modules/httpx"
	"github.com/MikeRoss27/scanforge/internal/modules/jssecrets"
	"github.com/MikeRoss27/scanforge/internal/modules/katana"
	"github.com/MikeRoss27/scanforge/internal/modules/naabu"
	"github.com/MikeRoss27/scanforge/internal/modules/nmap"
	"github.com/MikeRoss27/scanforge/internal/modules/nuclei"
	"github.com/MikeRoss27/scanforge/internal/modules/subfinder"
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
}

func New(configPath string) *App {
	return &App{
		ConfigPath:    configPath,
		ScopePrompter: newTerminalScopePrompter(),
	}
}

type RunOptions struct {
	Target       string
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

func (a *App) loadConfig() (*config.Config, error) {
	return config.Load(config.ResolvePath(a.ConfigPath))
}

func (a *App) Run(ctx context.Context, opts RunOptions) error {
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}

	if opts.Target == "" {
		return fmt.Errorf("target is required")
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
		return err
	}

	if _, err := cfg.ProfileModules(profile); err != nil {
		return err
	}
	if effective.proposal.Source == scopeSourceImplicit {
		if err := a.confirmScope(effective.proposal, opts.ConfirmScope); err != nil {
			return err
		}
	}

	store := storage.NewRunStore(config.WorkspaceDir(cfg))

	scanRun, err := store.Create(opts.Target)
	if err != nil {
		return fmt.Errorf("failed to create run directory: %w", err)
	}
	scanRun.Manifest.Profile = profile
	effectiveScopePath := scanRun.Path("00_meta", "effective-scope.txt")
	if err := effective.value.WriteFile(effectiveScopePath); err != nil {
		return fmt.Errorf("failed to persist effective scope: %w", err)
	}
	scanRun.Manifest.ScopePath = "00_meta/effective-scope.txt"
	scanRun.Manifest.ScopeSource = effective.proposal.Source
	scanRun.Manifest.ScopeMode = effective.proposal.Mode
	scanRun.Manifest.Outputs["effective_scope"] = scanRun.Manifest.ScopePath
	if err := scanRun.WriteManifest(); err != nil {
		return fmt.Errorf("failed to record effective scope in manifest: %w", err)
	}

	var executor runner.Executor

	if opts.DryRun {
		executor = runner.NewDryRunExecutor(opts.Verbose)
	} else {
		executor = runner.NewRealExecutor(opts.Verbose)
	}

	ascii.PrintBanner()
	fmt.Println(ui.Gray("  by MikeRoss"))
	fmt.Println()

	printRunInfoPanel(opts, profile, scanRun, *effective)

	registry := buildRegistry(cfg)

	orch := orchestrator.New(executor, registry)
	eventChan := make(chan orchestrator.Event)

	var results []*modules.Result
	var runErr error

	go func() {
		results, runErr = orch.Run(ctx, scanRun, orchestrator.Options{
			Target:          opts.Target,
			Profile:         profile,
			Config:          cfg,
			DryRun:          opts.DryRun,
			Verbose:         opts.Verbose,
			Scope:           effective.value,
			Proxy:           opts.Proxy,
			Headers:         opts.Headers,
			Nuclei:          opts.Nuclei,
			NmapConcurrency: opts.NmapConcurrency,
		}, eventChan)
	}()

	isInteractive := term.IsTerminal(int(os.Stdout.Fd()))

	if !opts.DryRun && isInteractive {
		model := tui.NewScanModel(eventChan)
		if _, err := tea.NewProgram(model).Run(); err != nil {
			return err
		}
	} else {
		for event := range eventChan {
			switch e := event.(type) {
			case orchestrator.WaveStartEvent:
				if opts.Verbose || !opts.DryRun {
					ui.Info("Wave %d: %s", e.Wave, strings.Join(e.Modules, ", "))
				}
			case orchestrator.ModuleStartEvent:
				if opts.Verbose {
					ui.Info("Running module %q...", e.Name)
				}
			case orchestrator.ModuleDoneEvent:
				if opts.Verbose || !opts.DryRun {
					msg := fmt.Sprintf("%s: %s (%s)", e.Name, e.Status, e.Dur.Round(time.Millisecond))
					if e.Failed {
						ui.Error("%s", msg)
					} else {
						ui.Success("%s", msg)
					}
				}
			case orchestrator.DeadlockEvent:
				ui.Warn("%s", e.Message)
			}
		}
	}

	scanRun.Manifest.CompletedAt = time.Now().Format(time.RFC3339)
	completedModules := 0
	for _, result := range results {
		if result.Status == "completed" {
			completedModules++
		}
	}
	switch {
	case runErr == nil && completedModules == len(results):
		scanRun.Manifest.Status = "completed"
	case completedModules == 0:
		scanRun.Manifest.Status = "failed"
	default:
		scanRun.Manifest.Status = "partial"
	}

	for _, result := range results {
		scanRun.Manifest.Modules = append(scanRun.Manifest.Modules, storage.ModuleResult{
			Name:   result.Name,
			Status: result.Status,
		})
		for key, value := range result.OutputFiles {
			scanRun.Manifest.Outputs[key] = value
		}
	}

	if writeErr := scanRun.WriteManifest(); writeErr != nil {
		return fmt.Errorf("failed to write manifest: %v (run error: %v)", writeErr, runErr)
	}

	fmt.Println()
	ui.Info("Generating report...")
	rep, reportErr := report.GenerateReport(scanRun.RootDir, &scanRun.Manifest)
	if reportErr != nil {
		ui.Warn("Failed to generate report: %v", reportErr)
	} else {
		jsonPath := filepath.Join(scanRun.RootDir, "report.json")
		mdPath := filepath.Join(scanRun.RootDir, "report.md")
		reportErr = errors.Join(rep.WriteJSON(jsonPath), rep.WriteMarkdown(mdPath))
		if reportErr != nil {
			ui.Warn("Failed to write report: %v", reportErr)
		} else {
			report.PrintTerminalSummary(rep)
		}
	}

	printRunSummaryBox(scanRun, results, rep)

	return errors.Join(runErr, reportErr)
}

// printRunInfoPanel renders a sleek bordered panel with the run configuration
// instead of the old full-width cyan block.
func printRunInfoPanel(opts RunOptions, profile string, scanRun *storage.Run, effective effectiveScope) {
	label := func(key, val string) string {
		return ui.Bold(ui.Cyan(key)) + " " + val
	}

	dryTag := ui.Green("OFF")
	if opts.DryRun {
		dryTag = ui.Yellow("ON")
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", label("TARGET ", opts.Target))
	fmt.Fprintf(&b, "%s\n", label("PROFILE", profile))
	fmt.Fprintf(&b, "%s\n", label("SCOPE  ", fmt.Sprintf("%s (%s, mode %s)", scanRun.Manifest.ScopePath, effective.proposal.Source, effective.proposal.Mode)))
	fmt.Fprintf(&b, "%s\n", label("DRY RUN", dryTag))
	fmt.Fprintf(&b, "%s", label("OUTPUT ", scanRun.RootDir))

	fmt.Println(ui.Box("⚡ Run Started", b.String()))
	fmt.Println()
}

// printRunSummaryBox renders a single, hard-to-miss closing panel. Unlike
// the mid-scroll module log and report.PrintTerminalSummary (which only
// prints when report generation succeeds), this always renders so a run
// never ends in just one easy-to-miss text line.
func printRunSummaryBox(scanRun *storage.Run, results []*modules.Result, rep *report.Report) {
	duration := "unknown"
	if started, err := time.Parse(time.RFC3339, scanRun.Manifest.StartedAt); err == nil {
		if completed, err := time.Parse(time.RFC3339, scanRun.Manifest.CompletedAt); err == nil {
			duration = completed.Sub(started).Round(time.Second).String()
		}
	}

	completedCount := 0
	var failedModules []string
	for _, res := range results {
		if res.Status == "completed" {
			completedCount++
		} else {
			failedModules = append(failedModules, fmt.Sprintf("%s (%s)", res.Name, res.Status))
		}
	}

	label := func(key, val string) string {
		return ui.Bold(ui.Magenta(key)) + " " + val
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", statusLine(scanRun.Manifest.Status))
	fmt.Fprintf(&b, "%s\n", label("DURATION ", duration))
	fmt.Fprintf(&b, "%s\n", label("MODULES  ", fmt.Sprintf("%d/%d completed", completedCount, len(results))))
	if len(failedModules) > 0 {
		fmt.Fprintf(&b, "%s\n", label("FAILED   ", ui.Red(strings.Join(failedModules, ", "))))
	}
	fmt.Fprintf(&b, "%s\n", label("FINDINGS ", formatSeverityCounts(countBySeverity(rep))))
	fmt.Fprintf(&b, "%s", label("OUTPUT   ", scanRun.RootDir))

	fmt.Println(ui.Box("🏁 Scan Summary", b.String()))
}

func statusLine(status string) string {
	text := "Status:    " + status
	switch status {
	case "completed":
		return ui.Green(text)
	case "partial":
		return ui.Yellow(text)
	default:
		return ui.Red(text)
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
	levels := []struct {
		key   string
		color func(string) string
	}{
		{"critical", ui.Red},
		{"high", ui.Red},
		{"medium", ui.Yellow},
		{"low", ui.Cyan},
		{"info", ui.Gray},
	}

	var parts []string
	total := 0
	for _, level := range levels {
		if n := counts[level.key]; n > 0 {
			parts = append(parts, level.color(fmt.Sprintf("%d %s", n, level.key)))
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
	registry.Register(dnsx.New(cfg.ToolPath("dnsx")))
	registry.Register(httpx.New(cfg.ToolPath("httpx")))
	registry.Register(naabu.New(cfg.ToolPath("naabu")))
	registry.Register(nmap.New(cfg.ToolPath("nmap")))
	registry.Register(whatweb.New(cfg.ToolPath("whatweb")))
	registry.Register(wafw00f.New(cfg.ToolPath("wafw00f")))
	registry.Register(katana.New(cfg.ToolPath("katana")))
	registry.Register(jssecrets.New())
	registry.Register(ffuf.New(cfg.ToolPath("ffuf")))
	registry.Register(nuclei.New(cfg.ToolPath("nuclei")))
	registry.Register(gau.New(cfg.ToolPath("gau")))
	registry.Register(tlsx.New(cfg.ToolPath("tlsx")))
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
		fmt.Printf("ScanForge Doctor v%s\n\n", version.Version)
		fmt.Print(doctor.FormatChecks(checks))
	}

	if exitCode != 0 {
		os.Exit(exitCode)
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
	fmt.Println("  1. Optionally edit scope.txt with your authorized targets")
	fmt.Println("  2. Run: scanforge doctor")
	fmt.Println("  3. Review: scanforge plan example.com")
	fmt.Println("  4. Run: scanforge run example.com --dry-run")

	return nil
}
