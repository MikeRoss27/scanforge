package modules

import (
	"context"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/runner"
)

type mockModule struct {
	name string
}

func (m *mockModule) Name() string { return m.name }
func (m *mockModule) Description() string { return "" }
func (m *mockModule) Requires() []string { return nil }
func (m *mockModule) Produces() []string { return nil }
func (m *mockModule) Run(ctx context.Context, runCtx *RunContext, executor runner.Executor) (*Result, error) {
	return nil, nil
}

func TestRegistry(t *testing.T) {
	reg := NewRegistry()

	if _, ok := reg.Get("missing"); ok {
		t.Fatal("expected Get on empty registry to return false")
	}

	reg.Register(&mockModule{name: "test1"})
	reg.Register(&mockModule{name: "test2"})

	m, ok := reg.Get("test1")
	if !ok || m.Name() != "test1" {
		t.Fatal("failed to get registered module")
	}

	resolved, err := reg.Resolve([]string{"test1", "test2"})
	if err != nil {
		t.Fatalf("unexpected error resolving modules: %v", err)
	}
	if len(resolved) != 2 {
		t.Fatalf("expected 2 resolved modules, got %d", len(resolved))
	}

	_, err = reg.Resolve([]string{"test1", "missing"})
	if err == nil {
		t.Fatal("expected error resolving missing module")
	}
}
