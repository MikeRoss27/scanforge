package orchestrator

import (
	"context"
	"errors"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

type cancelAfterModule struct {
	mockModule
	cancel context.CancelFunc
}

func (m *cancelAfterModule) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	result, err := m.mockModule.Run(ctx, runCtx, executor)
	m.cancel()
	return result, err
}

func TestCancellationDoesNotStartNextWave(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := modules.NewRegistry()
	reg.Register(&cancelAfterModule{mockModule: mockModule{name: "first", produces: []string{"hosts"}}, cancel: cancel})
	reg.Register(&mockModule{name: "pending", requires: []string{"hosts"}})
	cfg := config.Default()
	cfg.Profiles["test"] = []string{"first", "pending"}
	events := make(chan Event, 16)
	run := &storage.Run{RootDir: t.TempDir()}
	results, err := New(runner.NewDryRunExecutor(false), reg).Run(ctx, run, Options{
		Target: "example.com", Profile: "test", Config: cfg,
	}, events)
	if !errors.Is(err, ErrRunAborted) {
		t.Fatalf("expected abort, got %v", err)
	}
	if len(results) != 2 || results[0].Status != "completed" || results[1].Status != "aborted" {
		t.Fatalf("unexpected results: %+v", results)
	}
	for event := range events {
		switch e := event.(type) {
		case ModuleStartEvent:
			if e.Name == "pending" {
				t.Fatal("pending module started after cancellation")
			}
		case DeadlockEvent:
			t.Fatal("cancellation incorrectly reported as missing dependencies")
		}
	}
}
