package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/MikeRoss27/scanforge/internal/config"
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

	fmt.Println("ScanForge run")
	fmt.Println("Target: ", opts.Target)
	fmt.Println("Profile:", profile)
	fmt.Println("Scope:  ", scopeFile)
	fmt.Println("Dry run:", opts.DryRun)
	fmt.Println("Output: ", scanRun.RootDir)
	fmt.Println()

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

	fmt.Println()
	fmt.Println("Generating report...")
	rep, err := report.GenerateReport(scanRun.RootDir, &scanRun.Manifest)
	if err != nil {
		fmt.Printf("Warning: failed to generate report: %v\n", err)
	} else {
		jsonPath := filepath.Join(scanRun.RootDir, "report.json")
		mdPath := filepath.Join(scanRun.RootDir, "report.md")
		_ = rep.WriteJSON(jsonPath)
		_ = rep.WriteMarkdown(mdPath)
		
		// Print colorful summary to the terminal
		report.PrintTerminalSummary(rep)
	}

	fmt.Println("Done.")
	fmt.Println("Run directory:", scanRun.RootDir)

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
			fmt.Println("Created:", path)
		}
		for _, path := range result.Skipped {
			fmt.Println("Skipped:", path)
		}
		return err
	}

	for _, path := range result.Created {
		fmt.Println("Created:", path)
	}
	for _, path := range result.Skipped {
		fmt.Println("Skipped:", path)
	}

	fmt.Println()
	fmt.Println("Initialization complete.")
	fmt.Println("Next steps:")
	fmt.Println("  1. Edit scope.txt with your authorized targets")
	fmt.Println("  2. Run: scanforge doctor")
	fmt.Println("  3. Run: scanforge run example.com --dry-run")

	return nil
}
