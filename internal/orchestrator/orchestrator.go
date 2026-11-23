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
)

type Options struct {
	Target  string
	Profile string
	Config  *config.Config
	DryRun  bool
	Scope   *scanScope.Scope
	// Modules, when non-empty, is the exact module list to run instead of
	// resolving Profile through Config.ProfileModules. The caller
	// (app.prepareRun) has already applied --wp/--wp-bruteforce on top of
	// the profile's base list by the time it gets here; re-resolving from
	// Profile alone would silently drop that. Empty falls back to the old
	// behavior (profile-only resolution), which existing direct callers of
	// the orchestrator (tests) rely on.
	Modules []string

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
	// WordPress carries WordPress-engagement tuning.
	WordPress modules.WordPressOptions
	// Events enables the experimental discovery event bus (off by default).
	Events bool
	// ModuleStallTimeout overrides the default module stall detection
	// window (how long a module may run without output before the console is
	// warned that it appears stalled). Zero means the orchestrator default.
	ModuleStallTimeout time.Duration
	// ModuleStallCheckInterval overrides the stall watchdog cadence; zero
	// means the orchestrator default.
	ModuleStallCheckInterval time.Duration
}

// ErrRunAborted is returned when the run was intentionally aborted by the
// user (TUI quit or signal) rather than failing due to module errors.
var ErrRunAborted = errors.New("run aborted")

const (
	// defaultModuleStallTimeout is how long a module may run without any
	// progress, finding or module-level output before the orchestrator warns
	// that it appears stalled, so the operator is never left waiting blindly.
	defaultModuleStallTimeout = 15 * time.Minute
	// defaultModuleStallCheckInterval is how often running modules are
	// inspected for stall warnings.
	defaultModuleStallCheckInterval = 30 * time.Second
)

// moduleActivity tracks the runtime window of a module: when it started and
// when it last emitted progress, a finding or a module-level output.
type moduleActivity struct {
	startedAt  time.Time
	lastActive time.Time
}

// moduleStall is a running module that exceeded the stall window.
type moduleStall struct {
	name string
	idle time.Duration
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

func (o *Orchestrator) Run(ctx context.Context, scanRun *storage.Run, opts Options, outChan chan<- Event) ([]*modules.Result, error) {
	if outChan != nil {
		defer close(outChan)
	}

	if o.registry == nil {
		return nil, fmt.Errorf("module registry not configured")
	}

	moduleNames := opts.Modules
	if len(moduleNames) == 0 {
		var err error
		moduleNames, err = opts.Config.ProfileModules(opts.Profile)
		if err != nil {
			return nil, err
		}
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
	runCtx.WordPress = opts.WordPress
	if opts.Events {
		if err := runCtx.EnableEvents(); err != nil {
			return nil, fmt.Errorf("enable events: %w", err)
		}
	}

	// moduleActivity tracks, per module name, when it started and when it
	// last emitted progress or a finding. The stall watchdog watches this
	// map while modules run.
	var runningMu sync.Mutex
	running := make(map[string]*moduleActivity)

	if outChan != nil {
		// Modules may call this concurrently;
		// channel sends are inherently safe for concurrent use.
		runCtx.SetFindingSink(func(f modules.Finding) {
			runningMu.Lock()
			if act, ok := running[f.Module]; ok {
				act.lastActive = time.Now()
			}
			runningMu.Unlock()
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
		runCtx.SetProgressSink(func(e modules.ModuleProgressEvent) {
			runningMu.Lock()
			if act, ok := running[e.Name]; ok {
				act.lastActive = time.Now()
			}
			runningMu.Unlock()
			outChan <- ModuleProgressEvent{
				Name:    e.Name,
				Current: e.Current,
				Total:   e.Total,
				Unit:    e.Unit,
				Message: e.Message,
			}
		})
	}

	// StallWatchdog emits a warning through the event channel when a module
	// has run longer than the stall window without any progress or finding,
	// so a silent module surfaces as an error instead of hanging unseen.
	watchdogDone := make(chan struct{})
	watchdogStopped := make(chan struct{})
	defer func() {
		close(watchdogDone)
		<-watchdogStopped
	}()
	go func() {
		defer close(watchdogStopped)
		interval := defaultModuleStallCheckInterval
		if opts.ModuleStallCheckInterval > 0 {
			interval = opts.ModuleStallCheckInterval
		}
		timeout := defaultModuleStallTimeout
		if opts.ModuleStallTimeout > 0 {
			timeout = opts.ModuleStallTimeout
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-watchdogDone:
				return
			case <-ticker.C:
				now := time.Now()
				var stalled []moduleStall
				runningMu.Lock()
				for name, act := range running {
					if now.Sub(act.lastActive) < timeout {
						continue
					}
					stalled = append(stalled, moduleStall{name: name, idle: now.Sub(act.lastActive)})
				}
				runningMu.Unlock()
				for _, s := range stalled {
					if outChan != nil {
						outChan <- WarningEvent{Message: fmt.Sprintf("module %q stalled: no output for %s", s.name, s.idle)}
					}
				}
			}
		}
	}()

	dag, err := BuildDAG(selectedModules)
	if err != nil {
		return nil, err
	}
	for _, module := range selectedModules {
		for _, produced := range module.Produces() {
			runCtx.ExpectArtifact(produced)
		}
	}
	plan, err := BuildPlan(selectedModules)
	if err != nil {
		return nil, err
	}
	waveByModule := make(map[string]int, len(plan))
	for _, step := range plan {
		waveByModule[step.Name] = step.Wave
	}

	completed := make(map[string]bool)
	started := make(map[string]bool)
	availableArtifacts := make(map[string]bool)
	resultsByName := make(map[string]*modules.Result, len(selectedModules))
	var runErrors []error
	totalModules := len(selectedModules)
	runningCount := 0
	type moduleOutcome struct {
		module modules.Module
		result *modules.Result
		err    error
	}
	outcomes := make(chan moduleOutcome, totalModules)

	launch := func(m modules.Module) {
		go func() {
			start := time.Now()
			runningMu.Lock()
			running[m.Name()] = &moduleActivity{startedAt: start, lastActive: start}
			runningMu.Unlock()

			if outChan != nil {
				outChan <- ModuleStartEvent{Name: m.Name()}
			}

			// A per-module timeout (config module_timeouts) bounds the
			// whole module invocation, not just a single command: modules
			// run several commands (e.g. nuclei template update + scan)
			// and may stall between them. Zero means the module's own
			// default applies.
			moduleCtx := ctx
			timeout := moduleTimeout(opts.Config, m.Name())
			if timeout > 0 {
				var cancel context.CancelFunc
				moduleCtx, cancel = context.WithTimeout(ctx, timeout)
				defer cancel()
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
				result, err = m.Run(moduleCtx, runCtx, o.executor)
			}()

			// A deadline kill surfaces as context.DeadlineExceeded, which
			// hides what actually went wrong; translate it into a message
			// operators can act on.
			if err != nil && timeout > 0 && errors.Is(err, context.DeadlineExceeded) {
				err = fmt.Errorf("module %q timed out after %s: %w", m.Name(), timeout, err)
			}

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
				// A module that skipped itself (nothing applicable to do) is
				// not a failure: the console renders it as a single [SKIP].
				done := ModuleDoneEvent{Name: m.Name(), Status: status, Dur: time.Since(start), Failed: status != "completed" && status != "skipped", Summary: moduleSummary(runCtx, m, result)}
				if err == nil && result != nil {
					done.Reason = result.Reason
				}
				if err != nil {
					done.Error = err.Error()
					done.Kind = runner.ClassifyFailure(err)
				}
				outChan <- done
			}
			runningMu.Lock()
			delete(running, m.Name())
			runningMu.Unlock()

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
				outcomeErr := error(nil)
				if status != "aborted" {
					outcomeErr = fmt.Errorf("module %q failed: %w", m.Name(), err)
				}
				outcomes <- moduleOutcome{module: m, result: failedResult, err: outcomeErr}
				return
			}
			outcomes <- moduleOutcome{module: m, result: result}
		}()
	}

	consumeOutcome := func(outcome moduleOutcome) {
		name := outcome.module.Name()
		runningCount--
		completed[name] = true
		resultsByName[name] = outcome.result
		if outcome.err != nil {
			runErrors = append(runErrors, outcome.err)
		}
		// Artifacts become schedulable as soon as their producer finishes;
		// unrelated modules may still be running at this point.
		for _, produced := range outcome.module.Produces() {
			runCtx.CompleteArtifact(produced)
			if _, ok := runCtx.GetArtifact(produced); ok {
				availableArtifacts[produced] = true
			}
		}
	}

	for len(completed) < totalModules {
		if ctx.Err() != nil {
			if runningCount > 0 {
				consumeOutcome(<-outcomes)
				continue
			}
			for _, m := range selectedModules {
				if completed[m.Name()] {
					continue
				}
				result := &modules.Result{Name: m.Name(), Status: "aborted"}
				resultsByName[m.Name()] = result
				completed[m.Name()] = true
				if outChan != nil {
					outChan <- ModuleDoneEvent{Name: m.Name(), Status: "aborted"}
				}
			}
			break
		}

		readyModules := dag.NextReadyUnstarted(completed, started, availableArtifacts)
		if len(readyModules) > 0 {
			names := make([]string, 0, len(readyModules))
			for _, m := range readyModules {
				started[m.Name()] = true
				runningCount++
				names = append(names, m.Name())
			}
			if outChan != nil {
				outChan <- WaveStartEvent{Wave: waveByModule[readyModules[0].Name()], Modules: names}
			}
			for _, m := range readyModules {
				launch(m)
			}
			continue
		}

		if runningCount > 0 {
			consumeOutcome(<-outcomes)
			continue
		}

		// No runnable or running module remains: required artifacts were not
		// published by failed producers, so the remaining modules are skipped.
		if outChan != nil {
			outChan <- DeadlockEvent{Message: "No more modules can be run (dependencies missing). Marking remaining as skipped."}
		}
		if len(completed) == 0 {
			runErrors = append(runErrors, fmt.Errorf("orchestration stopped: required artifacts are unavailable"))
		}
		for _, m := range selectedModules {
			if completed[m.Name()] {
				continue
			}
			result := &modules.Result{Name: m.Name(), Status: "skipped"}
			resultsByName[m.Name()] = result
			completed[m.Name()] = true
			if outChan != nil {
				outChan <- ModuleDoneEvent{Name: m.Name(), Status: "skipped"}
			}
		}
	}

	// Completion order is intentionally decoupled from report order.
	results := make([]*modules.Result, 0, totalModules)
	for _, m := range selectedModules {
		results = append(results, resultsByName[m.Name()])
	}

	// An explicit abort (user quit, signal) is reported distinctly from a
	// failure so callers can map it to the appropriate exit code.
	if ctx.Err() != nil {
		return results, errors.Join(append(runErrors, ErrRunAborted)...)
	}
	return results, errors.Join(runErrors...)
}

// moduleTimeout returns the configured per-module timeout for name, or zero
// when none is set so the module's own default applies.
func moduleTimeout(cfg *config.Config, name string) time.Duration {
	if cfg == nil {
		return 0
	}
	return cfg.ModuleTimeouts[name]
}
