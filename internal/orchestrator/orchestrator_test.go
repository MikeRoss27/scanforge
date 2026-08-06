package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

type mockModule struct {
	name     string
	requires []string
	produces []string
	delay    time.Duration
	runErr   error
}

func (m *mockModule) Name() string        { return m.name }
func (m *mockModule) Description() string { return "" }
func (m *mockModule) Requires() []string  { return m.requires }
func (m *mockModule) Produces() []string  { return m.produces }
func (m *mockModule) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	time.Sleep(m.delay)
	if m.runErr != nil {
		return nil, m.runErr
	}
	for _, p := range m.produces {
		runCtx.AddArtifact(p, modules.Artifact{Name: p, Type: "test", Path: p})
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
