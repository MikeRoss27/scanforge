package orchestrator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/pterm/pterm"
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
			// This means we have a deadlock or unreachable modules due to failed dependencies.
			// Instead of returning an error, we mark the remaining modules as "skipped"
			// and gracefully finish the orchestration.
			if opts.Verbose {
				pterm.Warning.Println("No more modules can be run (dependencies missing). Marking remaining as skipped.")
			}
			for _, m := range selectedModules {
				if !completed[m.Name()] {
					results = append(results, &modules.Result{
						Name:   m.Name(),
						Status: "skipped",
						OutputFiles: map[string]string{
							"reason": "dependencies not met (upstream failure)",
						},
					})
					completed[m.Name()] = true
				}
			}
			break
		}

		if opts.Verbose {
			names := []string{}
			for _, m := range readyModules {
				names = append(names, m.Name())
			}
			pterm.Info.Printfln("Starting parallel wave: %v", names)
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
					pterm.Info.Printfln("Running module %q...", m.Name())
				}

				result, err := m.Run(ctx, runCtx, o.executor)
				
				if opts.Verbose {
					if err != nil {
						pterm.Error.Printfln("Module %q failed (%s)", m.Name(), time.Since(start).Round(time.Millisecond))
					} else {
						pterm.Success.Printfln("Module %q done (%s)", m.Name(), time.Since(start).Round(time.Millisecond))
					}
				}

				if err != nil {
					// Even if it failed, we want to record the result as failed
					waveResults <- &modules.Result{
						Name:   m.Name(),
						Status: "failed",
						OutputFiles: map[string]string{
							"error": err.Error(),
						},
					}
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

		// Check for errors in the wave but do not abort immediately
		var waveErrs []error
		for err := range waveErrors {
			waveErrs = append(waveErrs, err)
		}

		if len(waveErrs) > 0 {
			if opts.Verbose {
				for _, e := range waveErrs {
					pterm.Error.Printfln("Error in wave: %v", e)
				}
			}
		}

		// Process results
		for res := range waveResults {
			results = append(results, res)
			completed[res.Name] = true
			
			// Only add artifacts if the module completed successfully
			if res.Status == "completed" {
				m, _ := o.registry.Get(res.Name)
				for _, prod := range m.Produces() {
					mu.Lock()
					availableArtifacts[prod] = true
					mu.Unlock()
				}
			}
		}
	}

	return results, nil
}
