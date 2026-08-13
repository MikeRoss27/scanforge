package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

type mockModule struct {
	name         string
	requires     []string
	softRequires []string
	produces     []string
	delay        time.Duration
	runErr       error
	// outFiles are the OutputFiles a failed module returns alongside its
	// error, simulating partial output (e.g. nuclei killed by a timeout).
	outFiles map[string]string
}

func (m *mockModule) Name() string        { return m.name }
func (m *mockModule) Description() string { return "" }
func (m *mockModule) Requires() []string  { return m.requires }
func (m *mockModule) Produces() []string  { return m.produces }
func (m *mockModule) SoftRequires() []string {
	return m.softRequires
}
func (m *mockModule) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	time.Sleep(m.delay)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if m.runErr != nil {
		return &modules.Result{Name: m.name, Status: "failed", OutputFiles: m.outFiles}, m.runErr
	}
	for _, p := range m.produces {
		if err := runCtx.AddArtifact(p, modules.Artifact{Name: p, Type: "test", Path: p}); err != nil {
			return nil, err
		}
	}
	return &modules.Result{Name: m.name, Status: "completed"}, nil
}

func TestOrchestratorReturnsModuleFailuresAfterFinishingWave(t *testing.T) {
	reg := modules.NewRegistry()
	reg.Register(&mockModule{name: "failed", runErr: errors.New("boom")})
	reg.Register(&mockModule{name: "completed"})
	cfg := config.Default()
	cfg.Profiles["test"] = []string{"failed", "completed"}

	results, err := New(runner.NewDryRunExecutor(false), reg).Run(
		context.Background(), nil,
		Options{Target: "example.com", Profile: "test", Config: cfg},
		nil,
	)
	if err == nil || len(results) != 2 {
		t.Fatalf("Run() results=%d error=%v, want two results and an aggregate error", len(results), err)
	}
	if results[0].Status != "failed" || results[1].Status != "completed" {
		t.Fatalf("unexpected results: %+v", results)
	}
}

func TestOrchestratorKeepsPartialOutputOfFailedModule(t *testing.T) {
	reg := modules.NewRegistry()
	reg.Register(&mockModule{
		name:     "nuclei",
		runErr:   errors.New("signal: killed"),
		outFiles: map[string]string{"nuclei_raw": "06_vulns/nuclei.jsonl"},
	})

	cfg := config.Default()
	cfg.Profiles["test"] = []string{"nuclei"}

	results, err := New(runner.NewDryRunExecutor(false), reg).Run(
		context.Background(), nil,
		Options{Target: "example.com", Profile: "test", Config: cfg},
		nil,
	)
	if err == nil {
		t.Fatal("expected an aggregate error for the failed module")
	}
	if len(results) != 1 {
		t.Fatalf("result count = %d, want 1", len(results))
	}
	if results[0].Status != "failed" {
		t.Fatalf("status = %q, want failed", results[0].Status)
	}
	if results[0].OutputFiles["nuclei_raw"] != "06_vulns/nuclei.jsonl" {
		t.Fatalf("partial output files lost on failure, got %+v", results[0].OutputFiles)
	}
}

func TestOrchestratorKeepsProfileOrderWithinParallelWave(t *testing.T) {
	reg := modules.NewRegistry()
	reg.Register(&mockModule{name: "slow-first", delay: 20 * time.Millisecond})
	reg.Register(&mockModule{name: "fast-second"})

	cfg := config.Default()
	cfg.Profiles["test"] = []string{"slow-first", "fast-second"}

	results, err := New(runner.NewDryRunExecutor(false), reg).Run(
		context.Background(),
		nil,
		Options{Target: "example.com", Profile: "test", Config: cfg},
		nil,
	)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("result count = %d, want 2", len(results))
	}
	if results[0].Name != "slow-first" || results[1].Name != "fast-second" {
		t.Fatalf("result order = [%s, %s], want profile order", results[0].Name, results[1].Name)
	}
}

func TestOrchestratorMissingArtifact(t *testing.T) {
	reg := modules.NewRegistry()
	reg.Register(&mockModule{name: "needs_missing", requires: []string{"missing_artifact"}})

	cfg := config.Default()
	cfg.Profiles["test"] = []string{"needs_missing"}

	orch := New(runner.NewDryRunExecutor(false), reg)

	_, err := orch.Run(context.Background(), nil, Options{
		Target:  "example.com",
		Profile: "test",
		Config:  cfg,
	}, nil)

	if err == nil {
		t.Fatal("expected an invalid DAG error")
	}
}

func TestOrchestratorSuccess(t *testing.T) {
	reg := modules.NewRegistry()
	reg.Register(&mockModule{name: "producer", produces: []string{"test_art"}})
	reg.Register(&mockModule{name: "consumer", requires: []string{"test_art"}})

	cfg := config.Default()
	cfg.Profiles["test"] = []string{"producer", "consumer"}

	orch := New(runner.NewDryRunExecutor(false), reg)

	results, err := orch.Run(context.Background(), nil, Options{
		Target:  "example.com",
		Profile: "test",
		Config:  cfg,
	}, nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
}

// failedStatusModule publishes its artifacts but reports a non-completed
// status (as real tools do on non-zero exit codes); dependents must still see
// the artifacts and run.
type failedStatusModule struct {
	name     string
	requires []string
	produces []string
	status   string
}

func (m *failedStatusModule) Name() string        { return m.name }
func (m *failedStatusModule) Description() string { return "" }
func (m *failedStatusModule) Requires() []string  { return m.requires }
func (m *failedStatusModule) Produces() []string  { return m.produces }
func (m *failedStatusModule) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	for _, p := range m.produces {
		if err := runCtx.AddArtifact(p, modules.Artifact{Name: p, Type: "text", Path: "out.txt"}); err != nil {
			return nil, err
		}
	}
	return &modules.Result{Name: m.name, Status: m.status}, nil
}

func TestOrchestratorPublishesArtifactsOfFailedStatusModules(t *testing.T) {
	reg := modules.NewRegistry()
	reg.Register(&failedStatusModule{name: "producer", produces: []string{"test_art"}, status: "failed (exit code 1)"})
	reg.Register(&mockModule{name: "consumer", requires: []string{"test_art"}})

	cfg := config.Default()
	cfg.Profiles["test"] = []string{"producer", "consumer"}

	results, err := New(runner.NewDryRunExecutor(false), reg).Run(
		context.Background(), nil,
		Options{Target: "example.com", Profile: "test", Config: cfg},
		nil,
	)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(results) != 2 || results[0].Status == "completed" || results[1].Status != "completed" {
		t.Fatalf("results = %+v, want producer with failed status and a consumer that still ran", results)
	}
}

// nilResultModule violates the Module contract by returning (nil, nil).
type nilResultModule struct{ name string }

func (m *nilResultModule) Name() string        { return m.name }
func (m *nilResultModule) Description() string { return "" }
func (m *nilResultModule) Requires() []string  { return nil }
func (m *nilResultModule) Produces() []string  { return nil }
func (m *nilResultModule) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	return nil, nil
}

func TestOrchestratorHandlesNilResultWithoutPanicking(t *testing.T) {
	reg := modules.NewRegistry()
	reg.Register(&nilResultModule{name: "nil-module"})

	cfg := config.Default()
	cfg.Profiles["test"] = []string{"nil-module"}

	results, err := New(runner.NewDryRunExecutor(false), reg).Run(
		context.Background(), nil,
		Options{Target: "example.com", Profile: "test", Config: cfg},
		nil,
	)
	if err == nil {
		t.Fatal("expected an error for a module returning no result")
	}
	if len(results) != 1 || results[0].Status != "failed" {
		t.Fatalf("results = %+v, want a single failed result", results)
	}
}

// TestOrchestratorDeadlockDoesNotOverstate: a failed producer starves its
// dependents, which are marked "skipped" without turning the whole run into
// an "orchestration stopped" failure — the module's own error is the only
// error reported.
func TestOrchestratorDeadlockDoesNotOverstate(t *testing.T) {
	reg := modules.NewRegistry()
	reg.Register(&mockModule{name: "ok-producer", produces: []string{"art_a"}})
	reg.Register(&mockModule{name: "broken-producer", produces: []string{"art_b"}, runErr: errors.New("boom")})
	reg.Register(&mockModule{name: "blocked-consumer", requires: []string{"art_b"}})

	cfg := config.Default()
	cfg.Profiles["test"] = []string{"ok-producer", "broken-producer", "blocked-consumer"}

	results, err := New(runner.NewDryRunExecutor(false), reg).Run(
		context.Background(), nil,
		Options{Target: "example.com", Profile: "test", Config: cfg},
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected the module failure error, got %v", err)
	}
	if strings.Contains(err.Error(), "orchestration stopped") {
		t.Fatalf("a partial run must not be reported as orchestration failure: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("results = %d, want 3", len(results))
	}
	want := []string{"completed", "failed", "skipped"}
	for i, res := range results {
		if res.Status != want[i] {
			t.Fatalf("statuses = %q/%q/%q, want %v", results[0].Status, results[1].Status, results[2].Status, want)
		}
	}
}

// TestAbortCancelsRemainingModules covers the user-quit path: cancelling the
// context must mark running modules aborted, return ErrRunAborted, and never
// report "context canceled" as a module failure.
func TestAbortMarksModulesAborted(t *testing.T) {
	reg := modules.NewRegistry()
	reg.Register(&mockModule{name: "slow", delay: 100 * time.Millisecond})
	reg.Register(&mockModule{name: "pending", delay: 100 * time.Millisecond})

	cfg := config.Default()
	cfg.Profiles["test"] = []string{"slow", "pending"}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// Both modules are in flight (delay > cancel time) so they observe
		// the cancellation and must be marked "aborted".
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	results, err := New(runner.NewDryRunExecutor(false), reg).Run(
		ctx, nil,
		Options{Target: "example.com", Profile: "test", Config: cfg},
		nil,
	)
	if !errors.Is(err, ErrRunAborted) {
		t.Fatalf("expected ErrRunAborted, got %v", err)
	}
	if fmt.Sprint(err) == "context canceled" {
		t.Fatalf("abort must not be reported as a context failure, got %v", err)
	}
	for _, res := range results {
		if res.Status != "aborted" {
			t.Fatalf("result %q status = %q, want aborted", res.Name, res.Status)
		}
	}
}
