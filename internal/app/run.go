package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/console"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	"github.com/MikeRoss27/scanforge/internal/report"
	"github.com/MikeRoss27/scanforge/internal/runner"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

// Run resolves the target(s) — one positional target or a --targets file —
// and executes the profile against each of them, keeping per-target runs and
// reports separated under runs/<target>/. A failing target does not abort
// the rest of the engagement.
func (a *App) Run(ctx context.Context, opts RunOptions) error {
	opts, err := a.applyWizard(opts)
	if err != nil {
		return err
	}
	if opts.Workflow != "" {
		if err := checkWorkflowExclusive(opts.Profile, opts.WP); err != nil {
			return err
		}
		cfg, err := a.loadConfig()
		if err != nil {
			return err
		}
		if opts.compiled, err = loadWorkflow(cfg, opts.Workflow); err != nil {
			return fmt.Errorf("workflow: %w", err)
		}
		mergeWorkflowOverrides(&opts, opts.compiled.Overrides)
	}
	targets, err := expandTargets(opts.Target, opts.TargetsFile)
	if err != nil {
		return err
	}
	var errs []error
	for _, target := range targets {
		one := opts
		one.Target = target
		if err := a.runOne(ctx, one); err != nil {
			errs = append(errs, fmt.Errorf("target %s: %w", target, err))
		}
	}
	return errors.Join(errs...)
}

func (a *App) runOne(ctx context.Context, opts RunOptions) error {
	session, err := a.prepareRun(opts)
	if err != nil {
		return err
	}

	results, runErr := session.execute(ctx)

	manifestErr := session.finalizeManifest(results, runErr)
	rep := session.generateReports()
	session.printSummary(results, rep, runErr)

	if !opts.DryRun {
		if err := notifyWebhook(ctx, session.cfg, session.scanRun, rep); err != nil {
			session.console.Warn("webhook notification failed: %v", err)
		}
	}

	// Best-effort report parse warnings (session.reportErr) are already
	// printed and must not fail the run: a truncated tool output should
	// never flip a valid scan's exit code for CI pipelines.
	return errors.Join(runErr, manifestErr)
}

// printSummary renders the closing SCAN COMPLETE block and the triage hint
// when AI triage is configured for this workspace.
func (s *runSession) printSummary(results []*modules.Result, rep *report.Report, runErr error) {
	summary := buildSummary(s.scanRun, results, rep, s.cfg.AI.BaseURL != "")
	if errors.Is(runErr, orchestrator.ErrRunAborted) && summary.Status != "aborted" {
		summary.Status = "aborted"
	}
	s.console.PrintSummary(summary)
}

// prepareRun loads the config, resolves the profile and effective scope,
// creates the run directory with the effective scope persisted in the
// manifest, and builds the console renderer that owns every terminal write.
func (a *App) prepareRun(opts RunOptions) (*runSession, error) {
	cfg, err := a.loadConfig()
	if err != nil {
		return nil, err
	}

	if opts.Target == "" {
		return nil, fmt.Errorf("target is required")
	}

	profile := opts.Profile
	if profile == "" {
		profile = cfg.DefaultProfile
	}
	if opts.compiled != nil {
		profile = workflowProfilePrefix + opts.compiled.Name
	}

	effective, err := resolveScope(
		cfg,
		opts.Target,
		opts.Scope,
		opts.ScopeMode,
		opts.ScopeAdd,
		opts.Exclusions,
	)
	if err != nil {
		return nil, err
	}

	var moduleNames []string
	if opts.compiled != nil {
		// A workflow compiles to the exact module list a profile would
		// yield; nothing is appended to it.
		moduleNames = append(moduleNames, opts.compiled.Modules...)
	} else {
		moduleNames, err = cfg.ProfileModules(profile)
		if err != nil {
			return nil, err
		}
		moduleNames = applyWordPress(moduleNames, opts.WP, opts.WordPress.Bruteforce)
	}
	if opts.WordPress.Bruteforce && opts.WordPress.PasswordsFile == "" {
		return nil, fmt.Errorf("--wp-bruteforce requires --wp-passwords <file> (no password list is bundled)")
	}
	if effective.proposal.Source == scopeSourceImplicit {
		if err := a.confirmScope(effective.proposal, opts.ConfirmScope); err != nil {
			return nil, err
		}
	}

	// Only after scope is confirmed: the suggestion probe is itself live
	// network traffic against the target, so it must never run ahead of
	// that boundary.
	if opts.compiled == nil {
		moduleNames = a.maybeSuggestWordPress(opts, moduleNames)
	}

	store := storage.NewRunStore(config.WorkspaceDir(cfg))

	scanRun, err := store.Create(opts.Target)
	if err != nil {
		return nil, fmt.Errorf("failed to create run directory: %w", err)
	}
	scanRun.Manifest.Profile = profile
	effectiveScopePath := scanRun.Path("00_meta", "effective-scope.txt")
	if err := effective.value.WriteFile(effectiveScopePath); err != nil {
		return nil, fmt.Errorf("failed to persist effective scope: %w", err)
	}
	scanRun.Manifest.ScopePath = "00_meta/effective-scope.txt"
	scanRun.Manifest.ScopeSource = effective.proposal.Source
	scanRun.Manifest.ScopeMode = effective.proposal.Mode
	scanRun.Manifest.Outputs["effective_scope"] = scanRun.Manifest.ScopePath
	if err := scanRun.WriteManifest(); err != nil {
		return nil, fmt.Errorf("failed to record effective scope in manifest: %w", err)
	}

	out := os.Stdout
	term := console.DetectTerminal(out)
	session := &runSession{
		opts:        opts,
		profile:     profile,
		effective:   effective,
		moduleNames: moduleNames,
		scanRun:     scanRun,
		cfg:         cfg,
		term:        term,
		console: console.New(console.Options{
			Out:       out,
			Terminal:  term,
			Colors:    console.ColorEnabled(out),
			Verbosity: opts.Verbosity,
			Profile:   profile,
			DryRun:    opts.DryRun,
			Spinner:   console.ResolveSpinner(),
		}),
	}
	session.printIntro(len(moduleNames))
	return session, nil
}

// execute builds the registry and executor, then runs the orchestrator in a
// goroutine while the console renderer streams its events. The returned
// error is the orchestrator-level failure.
func (s *runSession) execute(ctx context.Context) ([]*modules.Result, error) {
	var executor runner.Executor
	if s.opts.DryRun {
		executor = runner.NewDryRunExecutor(s.executorVerbose(), runner.WithCommandSink(s.dryRunCommandSink()))
	} else {
		executor = runner.NewRealExecutor(s.executorVerbose(), runner.WithCommandSink(s.commandSink()))
	}

	registry := buildRegistry(s.cfg)
	if s.opts.compiled != nil {
		// Same registry API, modules wrapped with their step policy.
		wrapped, err := s.opts.compiled.Registry(registry)
		if err != nil {
			return nil, err
		}
		registry = wrapped
	}
	orch := orchestrator.New(executor, registry)
	// Buffered so a module emitting a burst of findings (e.g. nuclei) doesn't
	// block on the renderer catching up.
	eventChan := make(chan orchestrator.Event, 64)

	var results []*modules.Result
	var runErr error

	// runCtx is cancelled when the user interrupts the run (SIGINT via the
	// root command's signal context) so the scan actually stops instead of
	// lingering in the background.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// done synchronizes the results assignment with the consumer below: the
	// event channel is closed by orchestrator.Run before it returns, so
	// waiting on the channel alone would still race with the write to
	// results/runErr.
	done := make(chan struct{})
	go func() {
		defer close(done)
		results, runErr = orch.Run(runCtx, s.scanRun, orchestrator.Options{
			Target:          s.opts.Target,
			Profile:         s.profile,
			Modules:         s.moduleNames,
			Config:          s.cfg,
			DryRun:          s.opts.DryRun,
			Scope:           s.effective.value,
			Proxy:           s.opts.Proxy,
			Headers:         s.opts.Headers,
			Nuclei:          s.opts.Nuclei,
			Ffuf:            s.opts.Ffuf,
			NmapConcurrency: s.opts.NmapConcurrency,
			WordPress:       s.opts.WordPress,
		}, eventChan)
	}()

	s.consumeEvents(eventChan, done)
	return results, runErr
}

// executorVerbose keeps the executor's historical stderr diagnostics
// (stdout/stderr file hints) attached to exactly -v; -vv/-vvv replace
// them with structured console lines instead of duplicating them.
func (s *runSession) executorVerbose() bool {
	return s.opts.Verbosity == console.Verbose
}

// dryRunCommandSink prints the commands a dry run would execute. Unlike the
// -vv echo, dry-run commands are the point of the run and always show.
func (s *runSession) dryRunCommandSink() runner.CommandSink {
	return func(command runner.Command, _ *runner.CommandResult, _ error) {
		s.console.Command(command.Name + " " + strings.Join(command.Args, " "))
		if s.opts.Verbosity >= console.Verbose {
			if command.StdoutFile != "" {
				s.console.Debug("stdout → %s", command.StdoutFile)
			}
			if command.StderrFile != "" {
				s.console.Debug("stderr → %s", command.StderrFile)
			}
		}
	}
}

// commandSink returns the runner hook used by -vv/-vvv to echo the commands
// executed by external tools; nil (no hook) below Debug verbosity.
func (s *runSession) commandSink() runner.CommandSink {
	if s.opts.Verbosity < console.Debug {
		return nil
	}
	return func(command runner.Command, result *runner.CommandResult, err error) {
		echo := "$ " + command.Name + " " + strings.Join(command.Args, " ")
		s.console.Debug("%s", echo)
		if command.StdoutFile != "" {
			s.console.Debug("stdout → %s", command.StdoutFile)
		}
		if command.StderrFile != "" {
			s.console.Debug("stderr → %s", command.StderrFile)
		}
		if s.opts.Verbosity >= console.Trace {
			if result != nil && result.ExitCode != 0 {
				s.console.Warn("exit code %d", result.ExitCode)
			}
			if err != nil {
				s.console.Error("%v", err)
			}
		}
	}
}
