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

func TestBuildDAGSoftRequiresMissingProducerIsAllowed(t *testing.T) {
	consumer := &mockModule{
		name:         "consumer",
		requires:     []string{"hard_output"},
		softRequires: []string{"optional_output"},
	}
	producer := &mockModule{name: "producer", produces: []string{"hard_output"}}

	dag, err := BuildDAG([]modules.Module{producer, consumer})
	if err != nil {
		t.Fatalf("BuildDAG() error = %v, want success without the optional producer", err)
	}

	// Without the optional artifact the consumer is still ready once the
	// hard requirement is satisfied.
	ready := dag.NextReady(
		map[string]bool{"producer": true},
		map[string]bool{"hard_output": true},
	)
	if len(ready) != 1 || ready[0].Name() != "consumer" {
		t.Fatalf("ready modules = %v, want [consumer]", moduleNames(ready))
	}
}

func TestBuildDAGSoftRequiresGatesWhenProducerSelected(t *testing.T) {
	consumer := &mockModule{
		name:         "consumer",
		requires:     []string{"hard_output"},
		softRequires: []string{"optional_output"},
	}
	producer := &mockModule{name: "producer", produces: []string{"hard_output"}}
	optional := &mockModule{name: "optional", produces: []string{"optional_output"}}

	dag, err := BuildDAG([]modules.Module{producer, optional, consumer})
	if err != nil {
		t.Fatalf("BuildDAG() error = %v", err)
	}

	// The consumer must wait for the selected optional producer.
	ready := dag.NextReady(
		map[string]bool{"producer": true, "optional": true},
		map[string]bool{"hard_output": true},
	)
	if len(ready) != 0 {
		t.Fatalf("ready modules = %v, want none while the optional artifact is missing", moduleNames(ready))
	}

	ready = dag.NextReady(
		map[string]bool{"producer": true, "optional": true},
		map[string]bool{"hard_output": true, "optional_output": true},
	)
	if len(ready) != 1 || ready[0].Name() != "consumer" {
		t.Fatalf("ready modules = %v, want [consumer]", moduleNames(ready))
	}
}

func TestBuildDAGRejectsCycleThroughSoftRequires(t *testing.T) {
	_, err := BuildDAG([]modules.Module{
		&mockModule{name: "one", requires: []string{"two_output"}, produces: []string{"one_output"}},
		&mockModule{name: "two", softRequires: []string{"one_output"}, produces: []string{"two_output"}},
	})
	if err == nil || !strings.Contains(err.Error(), "dependency cycle") {
		t.Fatalf("BuildDAG() error = %v, want cycle error through soft requires", err)
	}
}

func moduleNames(mods []modules.Module) []string {
	names := make([]string, len(mods))
	for i, module := range mods {
		names[i] = module.Name()
	}
	return names
}
