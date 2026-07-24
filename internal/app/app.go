package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/MikeRoss27/scanforge/internal/ascii"
	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/doctor"
	"github.com/MikeRoss27/scanforge/internal/initcmd"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/modules/dnsx"
	"github.com/MikeRoss27/scanforge/internal/modules/ffuf"
	"github.com/MikeRoss27/scanforge/internal/modules/gau"
	"github.com/MikeRoss27/scanforge/internal/modules/httpx"
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
	"github.com/MikeRoss27/scanforge/internal/version"
	"github.com/pterm/pterm"
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

	pterm.DefaultHeader.WithFullWidth().WithBackgroundStyle(pterm.NewStyle(pterm.BgCyan)).WithTextStyle(pterm.NewStyle(pterm.FgBlack)).Println("ScanForge Run Started")

	pterm.Info.Printfln("Target:  %s", opts.Target)
	pterm.Info.Printfln("Profile: %s", profile)
	pterm.Info.Printfln("Scope:   %s (%s, mode %s)", scanRun.Manifest.ScopePath, effective.proposal.Source, effective.proposal.Mode)
	pterm.Info.Printfln("Dry run: %v", opts.DryRun)
	pterm.Info.Printfln("Output:  %s\n", scanRun.RootDir)

	registry := buildRegistry(cfg)

	orch := orchestrator.New(executor, registry)

	results, runErr := orch.Run(ctx, scanRun, orchestrator.Options{
		Target:  opts.Target,
		Profile: profile,
		Config:  cfg,
		DryRun:  opts.DryRun,
		Verbose: opts.Verbose,
		Scope:   effective.value,
	})

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

	pterm.Println()
	pterm.Info.Println("Generating report...")
	rep, reportErr := report.GenerateReport(scanRun.RootDir, &scanRun.Manifest)
	if reportErr != nil {
		pterm.Warning.Printfln("Failed to generate report: %v", reportErr)
	} else {
		jsonPath := filepath.Join(scanRun.RootDir, "report.json")
		mdPath := filepath.Join(scanRun.RootDir, "report.md")
		reportErr = errors.Join(rep.WriteJSON(jsonPath), rep.WriteMarkdown(mdPath))
		if reportErr != nil {
			pterm.Warning.Printfln("Failed to write report: %v", reportErr)
		} else {
			pterm.Success.Println("Report generated successfully")
			report.PrintTerminalSummary(rep)
		}
	}

	if scanRun.Manifest.Status == "completed" {
		pterm.Success.Printfln("Run completed. Directory: %s", scanRun.RootDir)
	} else {
		pterm.Warning.Printfln("Run %s. Directory: %s", scanRun.Manifest.Status, scanRun.RootDir)
	}

	return errors.Join(runErr, reportErr)
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
			pterm.Success.Printfln("Created: %s", path)
		}
		for _, path := range result.Skipped {
			pterm.Info.Printfln("Skipped: %s", path)
		}
		return err
	}

	for _, path := range result.Created {
		pterm.Success.Printfln("Created: %s", path)
	}
	for _, path := range result.Skipped {
		pterm.Info.Printfln("Skipped: %s", path)
	}

	pterm.Println()
	pterm.DefaultHeader.WithFullWidth().WithBackgroundStyle(pterm.NewStyle(pterm.BgGreen)).WithTextStyle(pterm.NewStyle(pterm.FgBlack)).Println("Initialization Complete")

	pterm.Info.Println("Next steps:")
	pterm.Println("  1. Optionally edit scope.txt with your authorized targets")
	pterm.Println("  2. Run: scanforge doctor")
	pterm.Println("  3. Review: scanforge plan example.com")
	pterm.Println("  4. Run: scanforge run example.com --dry-run")

	return nil
}
