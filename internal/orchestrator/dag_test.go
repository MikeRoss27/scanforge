package orchestrator

import (
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
)

func TestBuildDAGReturnsReadyModulesInProfileOrder(t *testing.T) {
	first := &mockModule{name: "first", produces: []string{"first_output"}}
	second := &mockModule{name: "second", produces: []string{"second_output"}}
	consumer := &mockModule{
		name:     "consumer",
		requires: []string{"first_output", "second_output"},
	}

	dag, err := BuildDAG([]modules.Module{second, first, consumer})
	if err != nil {
		t.Fatalf("BuildDAG() error = %v", err)
	}

	ready := dag.NextReady(map[string]bool{}, map[string]bool{})
	if len(ready) != 2 || ready[0].Name() != "second" || ready[1].Name() != "first" {
		t.Fatalf("initial ready modules = %v, want [second first]", moduleNames(ready))
	}

	ready = dag.NextReady(
		map[string]bool{"second": true, "first": true},
		map[string]bool{"first_output": true, "second_output": true},
	)
	if len(ready) != 1 || ready[0].Name() != "consumer" {
		t.Fatalf("next ready modules = %v, want [consumer]", moduleNames(ready))
	}
}

func TestBuildDAGRejectsMissingProducer(t *testing.T) {
	_, err := BuildDAG([]modules.Module{
		&mockModule{name: "consumer", requires: []string{"missing"}},
	})
	if err == nil || !strings.Contains(err.Error(), "no selected module produces it") {
		t.Fatalf("BuildDAG() error = %v, want missing producer error", err)
	}
}

func TestBuildDAGRejectsDuplicateProducer(t *testing.T) {
	_, err := BuildDAG([]modules.Module{
		&mockModule{name: "one", produces: []string{"shared"}},
		&mockModule{name: "two", produces: []string{"shared"}},
	})
	if err == nil || !strings.Contains(err.Error(), "multiple producers") {
		t.Fatalf("BuildDAG() error = %v, want duplicate producer error", err)
	}
}

func TestBuildDAGRejectsCycle(t *testing.T) {
	_, err := BuildDAG([]modules.Module{
		&mockModule{name: "one", requires: []string{"two_output"}, produces: []string{"one_output"}},
		&mockModule{name: "two", requires: []string{"one_output"}, produces: []string{"two_output"}},
	})
	if err == nil || !strings.Contains(err.Error(), "dependency cycle") {
		t.Fatalf("BuildDAG() error = %v, want cycle error", err)
	}
}

func moduleNames(mods []modules.Module) []string {
	names := make([]string, len(mods))
	for i, module := range mods {
		names[i] = module.Name()
	}
	return names
}
