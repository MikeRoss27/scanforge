package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/pterm/pterm"
	"github.com/MikeRoss27/scanforge/internal/doctor"
	"github.com/MikeRoss27/scanforge/internal/initcmd"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/modules/dnsx"
	"github.com/MikeRoss27/scanforge/internal/modules/ffuf"
	"github.com/MikeRoss27/scanforge/internal/modules/httpx"
	"github.com/MikeRoss27/scanforge/internal/modules/katana"
	"github.com/MikeRoss27/scanforge/internal/modules/naabu"
	"github.com/MikeRoss27/scanforge/internal/modules/nmap"
	"github.com/MikeRoss27/scanforge/internal/modules/nuclei"
	"github.com/MikeRoss27/scanforge/internal/modules/subfinder"
	"github.com/MikeRoss27/scanforge/internal/modules/wafw00f"
	"github.com/MikeRoss27/scanforge/internal/modules/whatweb"
	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	"github.com/MikeRoss27/scanforge/internal/report"
	"github.com/MikeRoss27/scanforge/internal/ascii"
	"github.com/MikeRoss27/scanforge/internal/runner"
	"github.com/MikeRoss27/scanforge/internal/scope"
	"github.com/MikeRoss27/scanforge/internal/storage"
	"github.com/MikeRoss27/scanforge/internal/version"
)

type App struct {
	ConfigPath string
}

func New(configPath string) *App {
	return &App{ConfigPath: configPath}
}

type RunOptions struct {
	Target  string
	Profile string
	Scope   string
	DryRun  bool
	Verbose bool
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

	scopeFile := opts.Scope
	if scopeFile == "" {
		scopeFile = cfg.DefaultScope
	}
	if scopeFile == "" {
		return fmt.Errorf("scope file is required (use --scope or set default_scope in scanforge.yaml)")
	}

	profile := opts.Profile
	if profile == "" {
		profile = cfg.DefaultProfile
	}

	loadedScope, err := scope.LoadFromFile(scopeFile)
	if err != nil {
		return err
	}

	if !loadedScope.IsAllowed(opts.Target) {
		return fmt.Errorf("target %q is not allowed by scope file %q", opts.Target, scopeFile)
	}

	if _, err := cfg.ProfileModules(profile); err != nil {
		return err
	}

	store := storage.NewRunStore(config.WorkspaceDir(cfg))

	scanRun, err := store.Create(opts.Target)
	if err != nil {
		return fmt.Errorf("failed to create run directory: %w", err)
	}
	scanRun.Manifest.Profile = profile

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
	pterm.Info.Printfln("Scope:   %s", scopeFile)
	pterm.Info.Printfln("Dry run: %v", opts.DryRun)
	pterm.Info.Printfln("Output:  %s\n", scanRun.RootDir)

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

	orch := orchestrator.New(executor, registry)

	results, err := orch.Run(ctx, scanRun, orchestrator.Options{
		Target:  opts.Target,
		Profile: profile,
		Config:  cfg,
		DryRun:  opts.DryRun,
		Verbose: opts.Verbose,
	})

	scanRun.Manifest.CompletedAt = time.Now().Format(time.RFC3339)
	if err != nil {
		scanRun.Manifest.Status = "failed"
	} else {
		scanRun.Manifest.Status = "completed"
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
		return fmt.Errorf("failed to write manifest: %v (run error: %v)", writeErr, err)
	}

	if err != nil {
		return err
	}

	pterm.Println()
	spinner, _ := pterm.DefaultSpinner.Start("Generating report...")
	rep, err := report.GenerateReport(scanRun.RootDir, &scanRun.Manifest)
	if err != nil {
		spinner.Warning(fmt.Sprintf("Failed to generate report: %v", err))
	} else {
		jsonPath := filepath.Join(scanRun.RootDir, "report.json")
		mdPath := filepath.Join(scanRun.RootDir, "report.md")
		_ = rep.WriteJSON(jsonPath)
		_ = rep.WriteMarkdown(mdPath)
		
		spinner.Success("Report generated successfully")
		report.PrintTerminalSummary(rep)
	}

	pterm.Success.Printfln("Run completed. Directory: %s", scanRun.RootDir)

	return nil
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
	pterm.Println("  1. Edit scope.txt with your authorized targets")
	pterm.Println("  2. Run: scanforge doctor")
	pterm.Println("  3. Run: scanforge run example.com --dry-run")

	return nil
}
