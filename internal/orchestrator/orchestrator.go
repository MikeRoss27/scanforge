package orchestrator

import (
	"context"
	"fmt"
	"sync"
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

	dag, err := BuildDAG(selectedModules)
	if err != nil {
		return nil, err
	}

	completed := make(map[string]bool)
	availableArtifacts := make(map[string]bool)
	var results []*modules.Result
	var mu sync.Mutex

	totalModules := len(selectedModules)

	// Loop until all modules are completed
	for len(completed) < totalModules {
		readyModules := dag.NextReady(completed, availableArtifacts)
		
		if len(readyModules) == 0 {
			// This means we have a deadlock: not all modules are completed but none are ready.
			// It implies missing artifacts that no un-run module produces.
			return results, fmt.Errorf("deadlock detected: unable to satisfy dependencies for remaining modules")
		}

		if opts.Verbose {
			names := []string{}
			for _, m := range readyModules {
				names = append(names, m.Name())
			}
			fmt.Printf("Starting parallel wave: %v\n", names)
		}

		var wg sync.WaitGroup
		waveResults := make(chan *modules.Result, len(readyModules))
		waveErrors := make(chan error, len(readyModules))

		for _, module := range readyModules {
			wg.Add(1)
			go func(m modules.Module) {
				defer wg.Done()
				start := time.Now()
				
				if opts.Verbose {
					fmt.Printf("Running module %q...\n", m.Name())
				}

				result, err := m.Run(ctx, runCtx, o.executor)
				
				if opts.Verbose {
					fmt.Printf("Module %q done (%s)\n", m.Name(), time.Since(start).Round(time.Millisecond))
				}

				if err != nil {
					waveErrors <- fmt.Errorf("module %q failed: %w", m.Name(), err)
					return
				}
				waveResults <- result
			}(module)
		}

		// Wait for all modules in this wave to finish
		wg.Wait()
		close(waveResults)
		close(waveErrors)

		// Check for errors in the wave
		if err := <-waveErrors; err != nil {
			return results, err
		}

		// Process results
		for res := range waveResults {
			results = append(results, res)
			completed[res.Name] = true
			
			// Get the module to see what it produced
			m, _ := o.registry.Get(res.Name)
			for _, prod := range m.Produces() {
				mu.Lock()
				availableArtifacts[prod] = true
				mu.Unlock()
			}
		}
	}

	return results, nil
}
