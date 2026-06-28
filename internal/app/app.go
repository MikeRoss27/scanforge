package app

import (
	"context"
	"fmt"

	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	"github.com/MikeRoss27/scanforge/internal/runner"
	"github.com/MikeRoss27/scanforge/internal/scope"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

type App struct{}

func New() *App {
	return &App{}
}

type RunOptions struct {
	Target  string
	Profile string
	Scope   string
	DryRun  bool
	Verbose bool
}

func (a *App) Run(ctx context.Context, opts RunOptions) error {
	if opts.Target == "" {
		return fmt.Errorf("target is required")
	}

	if opts.Scope == "" {
		return fmt.Errorf("scope file is required")
	}

	loadedScope, err := scope.LoadFromFile(opts.Scope)
	if err != nil {
		return err
	}

	if !loadedScope.IsAllowed(opts.Target) {
		return fmt.Errorf("target %q is not allowed by scope file %q", opts.Target, opts.Scope)
	}

	if _, err := orchestrator.ResolveModules(opts.Profile); err != nil {
		return err
	}

	store := storage.NewRunStore("runs")

	scanRun, err := store.Create(opts.Target)
	if err != nil {
		return fmt.Errorf("failed to create run directory: %w", err)
	}

	var executor runner.Executor

	if opts.DryRun {
		executor = runner.NewDryRunExecutor()
	} else {
		executor = runner.NewRealExecutor()
	}

	fmt.Println("ScanForge run")
	fmt.Println("Target: ", opts.Target)
	fmt.Println("Profile:", opts.Profile)
	fmt.Println("Scope:  ", opts.Scope)
	fmt.Println("Dry run:", opts.DryRun)
	fmt.Println("Output: ", scanRun.RootDir)
	fmt.Println()

	orch := orchestrator.New(executor)

	results, err := orch.Run(ctx, scanRun, orchestrator.Options{
		Target:  opts.Target,
		Profile: opts.Profile,
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

func (a *App) Doctor(ctx context.Context) error {
	fmt.Println("ScanForge Doctor")
	fmt.Println("Checking tools...")

	return nil
}

func (a *App) Init(ctx context.Context) error {
	fmt.Println("Initializing ScanForge config...")

	return nil
}
