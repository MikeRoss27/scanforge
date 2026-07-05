package orchestrator

import (
	"context"
	"fmt"
	"time"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

type Options struct {
	Target  string
	Profile string
	Config  *config.Config
	DryRun  bool
	Verbose bool
}

type Orchestrator struct {
	executor runner.Executor
	registry *modules.Registry
}

func New(executor runner.Executor, registry *modules.Registry) *Orchestrator {
	return &Orchestrator{
		executor: executor,
		registry: registry,
	}
}

func (o *Orchestrator) Run(ctx context.Context, scanRun *storage.Run, opts Options) ([]*modules.Result, error) {
	if o.registry == nil {
		return nil, fmt.Errorf("module registry not configured")
	}

	moduleNames, err := opts.Config.ProfileModules(opts.Profile)
	if err != nil {
		return nil, err
	}

	selectedModules, err := o.registry.Resolve(moduleNames)
	if err != nil {
		return nil, err
	}

	runCtx := modules.NewRunContext(opts.Target, opts.Profile, opts.DryRun, scanRun)
	results := make([]*modules.Result, 0, len(selectedModules))

	for _, module := range selectedModules {
		for _, req := range module.Requires() {
			if _, ok := runCtx.GetArtifact(req); !ok {
				return results, fmt.Errorf("module %q requires missing artifact %q", module.Name(), req)
			}
		}

		if opts.Verbose {
			fmt.Printf("Running module %q...\n", module.Name())
		}

		start := time.Now()
		result, err := module.Run(ctx, runCtx, o.executor)
		if err != nil {
			return results, fmt.Errorf("module %q failed: %w", module.Name(), err)
		}

		if opts.Verbose {
			fmt.Printf("Module %q done (%s)\n", module.Name(), time.Since(start).Round(time.Millisecond))
		}

		results = append(results, result)
	}

	return results, nil
}
