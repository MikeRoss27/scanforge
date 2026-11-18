package orchestrator

import (
	"context"
	"testing"
	"time"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

type gatedModule struct {
	name     string
	requires []string
	produces []string
	started  chan struct{}
	release  chan struct{}
}

func (m *gatedModule) Name() string        { return m.name }
func (m *gatedModule) Description() string { return "" }
func (m *gatedModule) Requires() []string  { return m.requires }
func (m *gatedModule) Produces() []string  { return m.produces }
func (m *gatedModule) Run(ctx context.Context, runCtx *modules.RunContext, _ runner.Executor) (*modules.Result, error) {
	close(m.started)
	select {
	case <-m.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	for _, artifact := range m.produces {
		if err := runCtx.AddArtifact(artifact, modules.Artifact{Name: artifact, Type: "test", Path: artifact}); err != nil {
			return nil, err
		}
	}
	return &modules.Result{Name: m.name, Status: "completed"}, nil
}

type signalingModule struct {
	name     string
	requires []string
	started  chan struct{}
}

type optionalArtifactWaiter struct {
	name     string
	artifact string
}

func (m *optionalArtifactWaiter) Name() string        { return m.name }
func (m *optionalArtifactWaiter) Description() string { return "" }
func (m *optionalArtifactWaiter) Requires() []string  { return nil }
func (m *optionalArtifactWaiter) Produces() []string  { return nil }
func (m *optionalArtifactWaiter) Run(ctx context.Context, runCtx *modules.RunContext, _ runner.Executor) (*modules.Result, error) {
	if _, _, err := runCtx.WaitArtifact(ctx, m.artifact); err != nil {
		return nil, err
	}
	return &modules.Result{Name: m.name, Status: "completed"}, nil
}

func (m *signalingModule) Name() string        { return m.name }
func (m *signalingModule) Description() string { return "" }
func (m *signalingModule) Requires() []string  { return m.requires }
func (m *signalingModule) Produces() []string  { return nil }
func (m *signalingModule) Run(context.Context, *modules.RunContext, runner.Executor) (*modules.Result, error) {
	close(m.started)
	return &modules.Result{Name: m.name, Status: "completed"}, nil
}

func TestReadyBranchAdvancesWhileUnrelatedModuleRuns(t *testing.T) {
	slowStarted := make(chan struct{})
	slowRelease := make(chan struct{})
	consumerStarted := make(chan struct{})

	reg := modules.NewRegistry()
	reg.Register(&gatedModule{name: "slow-independent", started: slowStarted, release: slowRelease})
	reg.Register(&mockModule{name: "producer", produces: []string{"hosts"}})
	reg.Register(&signalingModule{name: "consumer", requires: []string{"hosts"}, started: consumerStarted})
	cfg := config.Default()
	cfg.Profiles["test"] = []string{"slow-independent", "producer", "consumer"}

	type runResult struct {
		results []*modules.Result
		err     error
	}
	done := make(chan runResult, 1)
	go func() {
		results, err := New(runner.NewDryRunExecutor(false), reg).Run(
			context.Background(), nil,
			Options{Target: "example.com", Profile: "test", Config: cfg},
			nil,
		)
		done <- runResult{results: results, err: err}
	}()

	select {
	case <-slowStarted:
	case <-time.After(time.Second):
		t.Fatal("slow independent module did not start")
	}

	select {
	case <-consumerStarted:
		// The dependent branch advanced without waiting for slow-independent.
	case <-time.After(250 * time.Millisecond):
		close(slowRelease)
		t.Fatal("ready consumer was blocked by an unrelated running module")
	}
	close(slowRelease)

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("Run() error = %v", got.err)
		}
		if len(got.results) != 3 || got.results[0].Name != "slow-independent" || got.results[1].Name != "producer" || got.results[2].Name != "consumer" {
			t.Fatalf("results lost profile order: %+v", got.results)
		}
	case <-time.After(time.Second):
		t.Fatal("orchestrator did not finish after slow module was released")
	}
}

func TestOptionalArtifactWaiterWakesWhenProducerFails(t *testing.T) {
	reg := modules.NewRegistry()
	reg.Register(&mockModule{name: "optional-producer", produces: []string{"optional"}, runErr: context.DeadlineExceeded})
	reg.Register(&optionalArtifactWaiter{name: "waiter", artifact: "optional"})
	cfg := config.Default()
	cfg.Profiles["test"] = []string{"optional-producer", "waiter"}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	results, err := New(runner.NewDryRunExecutor(false), reg).Run(ctx, nil, Options{
		Target: "example.com", Profile: "test", Config: cfg,
	}, nil)
	if err == nil {
		t.Fatal("expected producer failure")
	}
	if len(results) != 2 || results[0].Status != "failed" || results[1].Status != "completed" {
		t.Fatalf("unexpected results: %+v", results)
	}
}
