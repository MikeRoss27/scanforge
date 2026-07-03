package app

import (
	"context"
	"fmt"
	"os"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/doctor"
	"github.com/MikeRoss27/scanforge/internal/initcmd"
	"github.com/MikeRoss27/scanforge/internal/orchestrator"
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

	var executor runner.Executor

	if opts.DryRun {
		executor = runner.NewDryRunExecutor(opts.Verbose)
	} else {
		executor = runner.NewRealExecutor(opts.Verbose)
	}

	fmt.Println("ScanForge run")
	fmt.Println("Target: ", opts.Target)
	fmt.Println("Profile:", profile)
	fmt.Println("Scope:  ", scopeFile)
	fmt.Println("Dry run:", opts.DryRun)
	fmt.Println("Output: ", scanRun.RootDir)
	fmt.Println()

	orch := orchestrator.New(executor)

	results, err := orch.Run(ctx, scanRun, orchestrator.Options{
		Target:  opts.Target,
		Profile: profile,
		Config:  cfg,
		Verbose: opts.Verbose,
	})
	if err != nil {
		scanRun.Manifest.Status = "failed"
		_ = scanRun.WriteManifest()
		return err
	}

	scanRun.Manifest.Status = "completed"

	for _, result := range results {
		for key, value := range result.OutputFiles {
			scanRun.Manifest.Outputs[key] = value
		}
	}

	if err := scanRun.WriteManifest(); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	fmt.Println()
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
