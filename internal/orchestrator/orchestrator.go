package orchestrator

import (
	"context"
	"fmt"

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
	selectedModules, err := ResolveModules(opts.Profile)
	if err != nil {
		return nil, err
	}

	results := make([]*modules.Result, 0, len(selectedModules))

	for _, module := range selectedModules {
		result, err := module.Run(ctx, scanRun, o.executor, opts.Target)
		if err != nil {
			return results, fmt.Errorf("module %q failed: %w", module.Name(), err)
		}

		results = append(results, result)
	}

	return results, nil
}

func ResolveModules(profile string) ([]modules.Module, error) {
	switch profile {
	case "passive":
		return []modules.Module{
			subfinder.New(),
			httpx.New(),
		}, nil

	case "web":
		return []modules.Module{
			subfinder.New(),
			httpx.New(),
			nuclei.New(),
		}, nil

	default:
		return nil, fmt.Errorf("unknown profile %q", profile)
	}
}
