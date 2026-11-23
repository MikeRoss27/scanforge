package app

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/MikeRoss27/scanforge/internal/benchmark"
	"github.com/MikeRoss27/scanforge/internal/console"
	"github.com/MikeRoss27/scanforge/internal/report"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

// BenchmarkOptions configures a single benchmark lab run.
type BenchmarkOptions struct {
	// Lab is the bundled lab name (see internal/benchmark.Labs()).
	Lab string
	// Target overrides the lab's own target, e.g. a self-hosted DVWA on a
	// different port, or a locally self-hosted Juice Shop instead of the
	// shared public demo.
	Target string
	// Timeout overrides the lab's own timeout.
	Timeout   time.Duration
	Verbosity console.Verbosity
	// DryRun skips the reachability probe and runs the pipeline in dry-run
	// mode (commands printed, nothing executed): useful to sanity-check the
	// wiring (profile, scope, module plan) without touching the network.
	DryRun bool
}

// BenchmarkAllOptions configures a run of every bundled lab.
type BenchmarkAllOptions struct {
	// Timeout overrides every lab's own timeout, if set.
	Timeout   time.Duration
	Verbosity console.Verbosity
	DryRun    bool
}

// Benchmark runs ScanForge's full pipeline against one bundled lab and
// scores the result. Unlike Run, it returns a structured benchmark.Score
// instead of printing: internal/cli/benchmark.go decides whether to render
// it as a human report or as the --json contract an AI agent or CI depends
// on. The only error this returns is a lookup failure (an unknown lab
// name) — every other problem (unreachable target, a failed scan, a
// missing report) is captured inside the returned Score so a human or an
// agent inspecting it sees exactly what happened.
func (a *App) Benchmark(ctx context.Context, opts BenchmarkOptions) (benchmark.Score, error) {
	lab, err := benchmark.LabByName(opts.Lab)
	if err != nil {
		return benchmark.Score{}, err
	}
	return a.runBenchmarkLab(ctx, lab, opts.Target, opts.Timeout, opts.Verbosity, opts.DryRun), nil
}

// BenchmarkAll runs every bundled lab, sequentially and never in parallel:
// several of them are shared public infrastructure (Firing Range,
// testphp.vulnweb.com, the Juice Shop demo), and hitting more than one at
// once for a benchmark run has no benefit and is simply ruder.
func (a *App) BenchmarkAll(ctx context.Context, opts BenchmarkAllOptions) ([]benchmark.Score, error) {
	labs, err := benchmark.Labs()
	if err != nil {
		return nil, err
	}
	scores := make([]benchmark.Score, 0, len(labs))
	for _, lab := range labs {
		scores = append(scores, a.runBenchmarkLab(ctx, lab, "", opts.Timeout, opts.Verbosity, opts.DryRun))
	}
	return scores, nil
}

func (a *App) runBenchmarkLab(ctx context.Context, lab benchmark.Lab, targetOverride string, timeoutOverride time.Duration, verbosity console.Verbosity, dryRun bool) benchmark.Score {
	target := lab.Target
	if targetOverride != "" {
		target = targetOverride
	}
	timeout := lab.Timeout
	if timeoutOverride > 0 {
		timeout = timeoutOverride
	}

	// A lab that needs manual setup (DVWA, chiefly) should fail fast with
	// its setup instructions instead of burning the full timeout running a
	// pipeline against a closed port. A dry run never touches the network
	// at all, so there is nothing to probe.
	if !dryRun {
		if err := checkReachable(ctx, target); err != nil {
			return benchmark.Score{
				Lab:    lab.Name,
				Target: target,
				Strict: lab.Strict,
				Error:  fmt.Sprintf("target unreachable, skipped: %v", err),
			}
		}
	}

	workspace, err := a.Workspace()
	if err != nil {
		return benchmark.Score{Lab: lab.Name, Target: target, Strict: lab.Strict, Error: err.Error()}
	}

	runCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	start := time.Now()
	runErr := a.Run(runCtx, RunOptions{
		Target:       target,
		Profile:      lab.Profile,
		ScopeMode:    lab.ScopeMode,
		ConfirmScope: true,
		Verbosity:    verbosity,
		DryRun:       dryRun,
	})
	duration := time.Since(start)

	// A run that errored partway through can still have written a
	// manifest and a partial report (the same "keep whatever exists
	// instead of discarding it" philosophy the rest of the pipeline
	// follows): always try to load and score whatever is on disk before
	// giving up.
	run, openErr := storage.LatestRun(workspace, target)
	if openErr != nil {
		errMsg := openErr.Error()
		if runErr != nil {
			errMsg = fmt.Sprintf("%v; %s", runErr, errMsg)
		}
		return benchmark.Score{Lab: lab.Name, Target: target, Strict: lab.Strict, DurationSecs: duration.Seconds(), Error: errMsg}
	}

	rep, loadErr := report.LoadFromFile(run.Path("report.json"))
	if loadErr != nil {
		rep = nil
	}

	score := benchmark.ScoreReport(lab, rep, run.Manifest.Status, duration)
	score.Target = target
	score.RunDir = run.RootDir
	switch {
	case runErr != nil:
		score.Error = runErr.Error()
	case loadErr != nil:
		score.Error = loadErr.Error()
	}
	return score
}

// checkReachable does a short, best-effort HTTP probe of target. Any HTTP
// response (even an error status) counts as reachable; only a transport
// failure (DNS, connection refused, timeout) does not. Some targets reject
// HEAD outright, so GET is tried as a fallback before giving up.
func checkReachable(ctx context.Context, target string) error {
	reachCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 5 * time.Second}
	if resp, err := doRequest(reachCtx, client, http.MethodHead, target); err == nil {
		_ = resp.Body.Close()
		return nil
	}
	resp, err := doRequest(reachCtx, client, http.MethodGet, target)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

func doRequest(ctx context.Context, client *http.Client, method, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}
