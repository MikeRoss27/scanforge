// Package orchestrator executes scan modules in dependency order using an
// artifact-driven DAG, running independent modules in parallel waves while
// enforcing scope filtering on produced artifacts.
package orchestrator

import (
	"fmt"

	"github.com/MikeRoss27/scanforge/internal/modules"
)

// DAG (Directed Acyclic Graph) represents the execution graph of modules
type DAG struct {
	nodes     map[string]*Node
	order     []string
	producers map[string]string
}

// Node represents a single module and its dependencies in the DAG
type Node struct {
	Module       modules.Module
	Requires     []string
	Produces     []string
	SoftRequires []string
}

// BuildDAG creates a dependency graph from a list of modules
func BuildDAG(mods []modules.Module) (*DAG, error) {
	dag := &DAG{
		nodes:     make(map[string]*Node, len(mods)),
		order:     make([]string, 0, len(mods)),
		producers: make(map[string]string),
	}

	for _, m := range mods {
		if m == nil {
			return nil, fmt.Errorf("module list contains a nil module")
		}
		name := m.Name()
		if name == "" {
			return nil, fmt.Errorf("module name cannot be empty")
		}
		if _, exists := dag.nodes[name]; exists {
			return nil, fmt.Errorf("duplicate module name %q", name)
		}

		node := &Node{
			Module:   m,
			Requires: m.Requires(),
			Produces: m.Produces(),
		}
		if soft, ok := m.(modules.SoftRequires); ok {
			node.SoftRequires = soft.SoftRequires()
		}
		dag.nodes[name] = node
		dag.order = append(dag.order, name)

		for _, artifact := range node.Produces {
			if artifact == "" {
				return nil, fmt.Errorf("module %q produces an artifact with an empty name", name)
			}
			if producer, exists := dag.producers[artifact]; exists {
				return nil, fmt.Errorf("artifact %q has multiple producers: %q and %q", artifact, producer, name)
			}
			dag.producers[artifact] = name
		}
	}

	for _, name := range dag.order {
		for _, artifact := range dag.nodes[name].Requires {
			if artifact == "" {
				return nil, fmt.Errorf("module %q requires an artifact with an empty name", name)
			}
			if _, exists := dag.producers[artifact]; !exists {
				return nil, fmt.Errorf("module %q requires artifact %q, but no selected module produces it", name, artifact)
			}
		}
		for _, artifact := range dag.nodes[name].SoftRequires {
			if artifact == "" {
				return nil, fmt.Errorf("module %q soft-requires an artifact with an empty name", name)
			}
		}
	}

	state := make(map[string]uint8, len(dag.nodes))
	for _, name := range dag.order {
		if err := visit(dag, name, state); err != nil {
			return nil, err
		}
	}

	return dag, nil
}

func visit(dag *DAG, name string, state map[string]uint8) error {
	switch state[name] {
	case 1:
		return fmt.Errorf("dependency cycle detected involving module %q", name)
	case 2:
		return nil
	}

	state[name] = 1
	for _, artifact := range dag.nodes[name].Requires {
		if err := visit(dag, dag.producers[artifact], state); err != nil {
			return err
		}
	}
	// Soft edges exist only when their producer is part of the profile; a
	// cycle through them is a genuine ordering deadlock and is rejected.
	for _, artifact := range dag.nodes[name].SoftRequires {
		if producer, ok := dag.producers[artifact]; ok {
			if err := visit(dag, producer, state); err != nil {
				return err
			}
		}
	}
	state[name] = 2
	return nil
}

// NextReady returns all modules whose dependencies are satisfied and haven't run yet.
func (d *DAG) NextReady(completed map[string]bool, availableArtifacts map[string]bool) []modules.Module {
	var ready []modules.Module

	for _, name := range d.order {
		node := d.nodes[name]
		// Skip if already completed
		if completed[name] {
			continue
		}

		// Check if all requirements are met
		canRun := true
		for _, req := range node.Requires {
			if !availableArtifacts[req] {
				canRun = false
				break
			}
		}
		// Soft requirements only gate execution when their producer is part
		// of the profile: the module must then wait for it, but a profile
		// without the producer must still run.
		if canRun {
			for _, req := range node.SoftRequires {
				if _, hasProducer := d.producers[req]; hasProducer && !availableArtifacts[req] {
					canRun = false
					break
				}
			}
		}

		if canRun {
			ready = append(ready, node.Module)
		}
	}

	return ready
}
