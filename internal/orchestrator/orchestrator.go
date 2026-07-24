package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
	scanScope "github.com/MikeRoss27/scanforge/internal/scope"
	"github.com/MikeRoss27/scanforge/internal/storage"
	"github.com/pterm/pterm"
)

type Options struct {
	Target  string
	Profile string
	Config  *config.Config
	DryRun  bool
	Verbose bool
	Scope   *scanScope.Scope
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

	runCtx := modules.NewRunContext(opts.Target, opts.Profile, opts.DryRun, scanRun, opts.Scope)

	dag, err := BuildDAG(selectedModules)
	if err != nil {
		return nil, err
	}

	completed := make(map[string]bool)
	availableArtifacts := make(map[string]bool)
	var results []*modules.Result
	var runErrors []error

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
			runErrors = append(runErrors, fmt.Errorf("orchestration stopped: required artifacts are unavailable"))
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
			runErrors = append(runErrors, waveErrs...)
			if opts.Verbose {
				for _, e := range waveErrs {
					pterm.Error.Printfln("Error in wave: %v", e)
				}
			}
		}

		// Process a parallel wave in profile order so results and artifact
		// publication remain deterministic regardless of goroutine completion.
		resultsByName := make(map[string]*modules.Result, len(readyModules))
		for res := range waveResults {
			resultsByName[res.Name] = res
		}
		for _, module := range readyModules {
			res := resultsByName[module.Name()]
			results = append(results, res)
			completed[res.Name] = true

			// Only add artifacts if the module completed successfully
			if res.Status == "completed" {
				for _, prod := range module.Produces() {
					if _, ok := runCtx.GetArtifact(prod); !ok {
						continue
					}
					availableArtifacts[prod] = true
				}
			}
		}
	}

	return results, errors.Join(runErrors...)
}
