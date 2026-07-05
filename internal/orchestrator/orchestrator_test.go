package orchestrator

import (
	"context"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

type mockModule struct {
	name     string
	requires []string
	produces []string
}

func (m *mockModule) Name() string                        { return m.name }
func (m *mockModule) Description() string                 { return "" }
func (m *mockModule) Requires() []string                  { return m.requires }
func (m *mockModule) Produces() []string                  { return m.produces }
func (m *mockModule) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	for _, p := range m.produces {
		runCtx.AddArtifact(p, modules.Artifact{Name: p, Type: "test", Path: p})
	}
	return &modules.Result{Name: m.name, Status: "completed"}, nil
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
	})

	if err == nil {
		t.Fatal("expected error due to missing artifact")
	}

	if err.Error() != `module "needs_missing" requires missing artifact "missing_artifact"` {
		t.Fatalf("unexpected error message: %v", err)
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
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
}
