package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/console"
)

// benchmarkTestApp returns an App whose workspace is a throwaway temp
// directory, so a benchmark run under test never writes into the repo's
// own runs/ directory.
func benchmarkTestApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "scanforge.yaml")
	workspace := filepath.Join(dir, "runs")
	content := "workspace: " + workspace + "\n"
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return New(configPath)
}

// TestBenchmarkDryRunMakesNoNetworkCall proves the full wiring (Benchmark
// -> Run -> LatestRun -> LoadFromFile -> ScoreReport) end to end without
// ever touching the network: DryRun both skips the reachability probe and
// runs the pipeline through the dry-run executor, exactly like `scanforge
// run --dry-run` does for a normal scan.
//
// A dry run of any real profile predictably reports dnsbrute as failed
// (DryRunExecutor never writes subfinder's output, so dnsbrute correctly
// refuses to brute-force an empty subdomain list) — that is an existing,
// intentional module behavior unrelated to this feature, so this test
// only asserts the parts that are: the run happened, produced a loadable
// report, and Score carries that run's location.
func TestBenchmarkDryRunMakesNoNetworkCall(t *testing.T) {
	a := benchmarkTestApp(t)

	score, err := a.Benchmark(context.Background(), BenchmarkOptions{
		Lab:       "firing-range",
		Verbosity: console.Quiet,
		DryRun:    true,
	})
	if err != nil {
		t.Fatalf("Benchmark() error = %v", err)
	}
	if score.Lab != "firing-range" {
		t.Fatalf("Score.Lab = %q, want firing-range", score.Lab)
	}
	if score.RunDir == "" {
		t.Fatal("Score.RunDir is empty: LatestRun/report loading did not wire through")
	}
	if _, err := os.Stat(score.RunDir); err != nil {
		t.Fatalf("Score.RunDir %q does not exist: %v", score.RunDir, err)
	}
	if _, err := os.Stat(filepath.Join(score.RunDir, "report.json")); err != nil {
		t.Fatalf("report.json was not written at %q: %v", score.RunDir, err)
	}
}

func TestBenchmarkUnknownLab(t *testing.T) {
	a := benchmarkTestApp(t)
	if _, err := a.Benchmark(context.Background(), BenchmarkOptions{Lab: "not-a-real-lab", DryRun: true}); err == nil {
		t.Fatal("expected an error for an unknown lab name")
	}
}

func TestBenchmarkTargetOverride(t *testing.T) {
	a := benchmarkTestApp(t)
	score, err := a.Benchmark(context.Background(), BenchmarkOptions{
		Lab:       "dvwa",
		Target:    "http://localhost:59999", // never reachable, and DryRun means it's never even probed
		Verbosity: console.Quiet,
		DryRun:    true,
	})
	if err != nil {
		t.Fatalf("Benchmark() error = %v", err)
	}
	if score.Target != "http://localhost:59999" {
		t.Fatalf("Score.Target = %q, want the override to take effect", score.Target)
	}
}

func TestBenchmarkAllRunsEveryLab(t *testing.T) {
	a := benchmarkTestApp(t)
	scores, err := a.BenchmarkAll(context.Background(), BenchmarkAllOptions{
		Verbosity: console.Quiet,
		DryRun:    true,
	})
	if err != nil {
		t.Fatalf("BenchmarkAll() error = %v", err)
	}
	if len(scores) != 4 {
		t.Fatalf("BenchmarkAll() returned %d scores, want 4", len(scores))
	}
}

func TestBenchmarkReachabilityCheckSkipsRealScanWhenUnreachable(t *testing.T) {
	a := benchmarkTestApp(t)
	// DryRun is deliberately false here: this is the one test that exercises
	// checkReachable for real, against a closed local port chosen so the
	// connection fails immediately (no real network dependency, no
	// external host contacted) instead of running the full pipeline.
	score, err := a.Benchmark(context.Background(), BenchmarkOptions{
		Lab:       "dvwa",
		Target:    "http://127.0.0.1:1",
		Verbosity: console.Quiet,
	})
	if err != nil {
		t.Fatalf("Benchmark() error = %v", err)
	}
	if score.Error == "" {
		t.Fatal("expected an unreachable-target error")
	}
	if score.RunDir != "" {
		t.Fatalf("RunDir = %q, want empty: the pipeline must never have run", score.RunDir)
	}
}
