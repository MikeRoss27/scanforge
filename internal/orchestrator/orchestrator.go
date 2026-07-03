package orchestrator

import (
	"context"
	"fmt"
	"time"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/modules/httpx"
	"github.com/MikeRoss27/scanforge/internal/modules/nuclei"
	"github.com/MikeRoss27/scanforge/internal/modules/subfinder"
	"github.com/MikeRoss27/scanforge/internal/runner"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

type Options struct {
	Target  string
	Profile string
	Config  *config.Config
	Verbose bool
}

type Orchestrator struct {
	executor runner.Executor
}

func New(executor runner.Executor) *Orchestrator {
	return &Orchestrator{
		executor: executor,
	}
}

func (o *Orchestrator) Run(ctx context.Context, scanRun *storage.Run, opts Options) ([]*modules.Result, error) {
	selectedModules, err := ResolveModules(opts.Profile, opts.Config)
	if err != nil {
		return nil, err
	}

	results := make([]*modules.Result, 0, len(selectedModules))

	for _, module := range selectedModules {
		if opts.Verbose {
			fmt.Printf("Running module %q...\n", module.Name())
		}

		start := time.Now()
		result, err := module.Run(ctx, scanRun, o.executor, opts.Target)
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

func ResolveModules(profile string, cfg *config.Config) ([]modules.Module, error) {
	if cfg == nil {
		cfg = config.Default()
	}

	moduleNames, err := cfg.ProfileModules(profile)
	if err != nil {
		return nil, err
	}

	resolved := make([]modules.Module, 0, len(moduleNames))

	for _, name := range moduleNames {
		switch name {
		case "subfinder":
			resolved = append(resolved, subfinder.New(cfg.ToolPath("subfinder")))
		case "httpx":
			resolved = append(resolved, httpx.New(cfg.ToolPath("httpx")))
		case "nuclei":
			resolved = append(resolved, nuclei.New(cfg.ToolPath("nuclei")))
		default:
			return nil, fmt.Errorf("unknown module %q in profile %q", name, profile)
		}
	}

	return resolved, nil
}
