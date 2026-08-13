package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
	scanScope "github.com/MikeRoss27/scanforge/internal/scope"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

type Options struct {
	Target  string
	Profile string
	Config  *config.Config
	DryRun  bool
	Verbose bool
	Scope   *scanScope.Scope

	// Proxy routes HTTP-capable modules through an intercepting proxy such
	// as Caido or Burp Suite (e.g. http://127.0.0.1:8080).
	Proxy string
	// Headers are applied to every outgoing HTTP request, for example to
	// carry an authenticated session (Cookie/Authorization).
	Headers []string
	// Nuclei carries nuclei-specific tuning (severity, tags, rate limiting).
	Nuclei modules.NucleiOptions
	// Ffuf carries ffuf-specific tuning (wordlist, status-code filtering).
	Ffuf modules.FfufOptions
	// NmapConcurrency bounds how many nmap processes run at once.
	NmapConcurrency int
}

// ErrRunAborted is returned when the run was intentionally aborted by the
// user (TUI quit or signal) rather than failing due to module errors.
var ErrRunAborted = errors.New("run aborted")

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

func (o *Orchestrator) Run(ctx context.Context, scanRun *storage.Run, opts Options, outChan chan<- Event) ([]*modules.Result, error) {
	if outChan != nil {
		defer close(outChan)
	}

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
	runCtx.Proxy = opts.Proxy
	runCtx.Headers = opts.Headers
	runCtx.Nuclei = opts.Nuclei
	runCtx.Ffuf = opts.Ffuf
	runCtx.NmapConcurrency = opts.NmapConcurrency

	if outChan != nil {
		// Modules may call this concurrently (multiple modules run per wave);
		// channel sends are inherently safe for concurrent use.
		runCtx.SetFindingSink(func(f modules.Finding) {
			outChan <- FindingEvent{
				Module:   f.Module,
				Severity: f.Severity,
				Title:    f.Title,
				Target:   f.Target,
				Detail:   f.Detail,
			}
		})
		runCtx.SetWarningSink(func(message string) {
			outChan <- WarningEvent{Message: message}
		})
	}

	dag, err := BuildDAG(selectedModules)
	if err != nil {
		return nil, err
	}

	completed := make(map[string]bool)
	availableArtifacts := make(map[string]bool)
	var results []*modules.Result
	var runErrors []error

	totalModules := len(selectedModules)
	wave := 0

	// Loop until all modules are completed
	for len(completed) < totalModules {
		wave++
		readyModules := dag.NextReady(completed, availableArtifacts)

		if len(readyModules) == 0 {
			// This means we have a deadlock or unreachable modules due to failed
			// dependencies (or the run was aborted). Instead of returning an
			// error, we mark the remaining modules as "skipped" (or "aborted"
			// when the context was cancelled) and gracefully finish the
			// orchestration.
			status := "skipped"
			if ctx.Err() != nil {
				status = "aborted"
			}
			if outChan != nil {
				outChan <- DeadlockEvent{Message: "No more modules can be run (dependencies missing). Marking remaining as " + status + "."}
			}
			// A partially failed pipeline is the documented "skipped" behavior:
			// only surface an error when nothing at all completed.
			if ctx.Err() == nil && len(completed) == 0 {
				runErrors = append(runErrors, fmt.Errorf("orchestration stopped: required artifacts are unavailable"))
			}
			for _, m := range selectedModules {
				if completed[m.Name()] {
					continue
				}
				results = append(results, &modules.Result{
					Name:   m.Name(),
					Status: status,
				})
				completed[m.Name()] = true
				if outChan != nil {
					outChan <- ModuleDoneEvent{Name: m.Name(), Status: status}
				}
			}
			break
		}

		names := make([]string, 0, len(readyModules))
		for _, m := range readyModules {
			names = append(names, m.Name())
		}
		if outChan != nil {
			outChan <- WaveStartEvent{Wave: wave, Modules: names}
		}

		var wg sync.WaitGroup
		waveResults := make(chan *modules.Result, len(readyModules))
		waveErrors := make(chan error, len(readyModules))

		for _, module := range readyModules {
			wg.Add(1)
			go func(m modules.Module) {
				defer wg.Done()
				start := time.Now()

				if outChan != nil {
					outChan <- ModuleStartEvent{Name: m.Name()}
				}

				// A panicking module (third-party library bug, unexpected
				// input shape) must surface as a failure, not crash the whole
				// scan: without the recovery, the goroutine would never send
				// its result and resultsByName below would see a nil entry.
				var result *modules.Result
				var err error
				func() {
					defer func() {
						if r := recover(); r != nil {
							result, err = nil, fmt.Errorf("module %q panicked: %v", m.Name(), r)
						}
					}()
					result, err = m.Run(ctx, runCtx, o.executor)
				}()

				// A module returning (nil, nil) violates the contract; treat it
				// as a failure instead of letting a nil result panic downstream.
				if result == nil && err == nil {
					err = fmt.Errorf("module %q returned no result", m.Name())
				}

				status := "failed"
				if err == nil {
					status = result.Status
				} else if errors.Is(err, context.Canceled) {
					// User-initiated abort: not a module failure.
					status = "aborted"
				}
				if outChan != nil {
					outChan <- ModuleDoneEvent{Name: m.Name(), Status: status, Dur: time.Since(start), Failed: status != "completed", Summary: moduleSummary(runCtx, m, result)}
				}

				if err != nil {
					// Even if it failed, we want to record the result in a way
					// that reflects what happened. A failed module may still
					// have produced partial output (e.g. nuclei killed by a
					// timeout halfway through its scan): keep its OutputFiles
					// so the report engine can parse whatever was written.
					failedResult := &modules.Result{
						Name:   m.Name(),
						Status: status,
					}
					if result != nil {
						failedResult.OutputFiles = result.OutputFiles
					}
					waveResults <- failedResult
					if status != "aborted" {
						waveErrors <- fmt.Errorf("module %q failed: %w", m.Name(), err)
					}
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
				// Diagnostics go to stderr so they never corrupt a Bubble Tea
				// render loop that owns stdout.
				for _, e := range waveErrs {
					fmt.Fprintf(os.Stderr, "ERROR: %v\n", e)
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

			// Register artifacts by what was actually published, not by the
			// human-readable status: tools routinely exit non-zero (nmap on
			// down hosts, dnsx on failed query batches) while still producing
			// valid, scope-filtered output that dependents must consume.
			for _, prod := range module.Produces() {
				if _, ok := runCtx.GetArtifact(prod); ok {
					availableArtifacts[prod] = true
				}
			}
		}
	}

	// An explicit abort (user quit, signal) is reported distinctly from a
	// failure so callers can map it to the appropriate exit code.
	if ctx.Err() != nil {
		return results, errors.Join(append(runErrors, ErrRunAborted)...)
	}
	return results, errors.Join(runErrors...)
}
