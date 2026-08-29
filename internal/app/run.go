package app

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/MikeRoss27/scanforge/internal/ascii"
	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	"github.com/MikeRoss27/scanforge/internal/runner"
	"github.com/MikeRoss27/scanforge/internal/storage"
	"github.com/MikeRoss27/scanforge/internal/ui"
	"github.com/MikeRoss27/scanforge/internal/version"
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
	printRunSummaryBox(os.Stdout, session.scanRun, results, rep)
	printFindingsTable(rep)

	if !opts.DryRun {
		if err := notifyWebhook(ctx, session.cfg, session.scanRun, rep); err != nil {
			ui.Warn("Webhook notification failed: %v", err)
		}
	}

	// Best-effort report parse warnings (session.reportErr) are already
	// printed and must not fail the run: a truncated tool output should
	// never flip a valid scan's exit code for CI pipelines.
	return errors.Join(runErr, manifestErr)
}

// prepareRun loads the config, resolves the profile and effective scope, and
// creates the run directory with the effective scope persisted in the
// manifest.
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

	if _, err := cfg.ProfileModules(profile); err != nil {
		return nil, err
	}
	if effective.proposal.Source == scopeSourceImplicit {
		if err := a.confirmScope(effective.proposal, opts.ConfirmScope); err != nil {
			return nil, err
		}
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

	return &runSession{
		opts:      opts,
		profile:   profile,
		effective: effective,
		scanRun:   scanRun,
		cfg:       cfg,
	}, nil
}

// execute builds the registry and executor, then runs the orchestrator in a
// goroutine while its events are consumed on the terminal. The returned error
// is the orchestrator-level failure; a TUI startup error aborts the run early.
func (s *runSession) execute(ctx context.Context) ([]*modules.Result, error) {
	var executor runner.Executor
	if s.opts.DryRun {
		executor = runner.NewDryRunExecutor(s.opts.Verbose)
	} else {
		executor = runner.NewRealExecutor(s.opts.Verbose)
	}

	ascii.PrintBanner()
	fmt.Println(ui.Dim("  by MikeRoss · v" + version.Version))
	fmt.Println()

	printRunInfoPanel(s.opts, s.profile, s.scanRun, *s.effective)

	orch := orchestrator.New(executor, buildRegistry(s.cfg))
	eventChan := make(chan orchestrator.Event)

	var results []*modules.Result
	var runErr error

	// runCtx is cancelled when the user quits the TUI early so the scan
	// actually stops instead of lingering in the background.
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
			Config:          s.cfg,
			DryRun:          s.opts.DryRun,
			Verbose:         s.opts.Verbose,
			Scope:           s.effective.value,
			Proxy:           s.opts.Proxy,
			Headers:         s.opts.Headers,
			Nuclei:          s.opts.Nuclei,
			Ffuf:            s.opts.Ffuf,
			NmapConcurrency: s.opts.NmapConcurrency,
		}, eventChan)
	}()

	if err := s.consumeEvents(cancel, eventChan, done); err != nil {
		// The TUI failed, but the orchestrator still ran: keep its results so
		// the manifest and reports reflect what actually happened.
		return results, errors.Join(runErr, err)
	}
	return results, runErr
}
