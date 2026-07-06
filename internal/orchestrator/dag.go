package orchestrator

import (
	"fmt"

	"github.com/MikeRoss27/scanforge/internal/modules"
)

// DAG (Directed Acyclic Graph) represents the execution graph of modules
type DAG struct {
	nodes map[string]*Node
}

// Node represents a single module and its dependencies in the DAG
type Node struct {
	Module   modules.Module
	Requires []string
	Produces []string
}

// BuildDAG creates a dependency graph from a list of modules
func BuildDAG(mods []modules.Module) (*DAG, error) {
	dag := &DAG{
		nodes: make(map[string]*Node),
	}

	for _, m := range mods {
		dag.nodes[m.Name()] = &Node{
			Module:   m,
			Requires: m.Requires(),
			Produces: m.Produces(),
		}
	}

	// Simple cycle detection (can be improved)
	for name := range dag.nodes {
		if hasCycle(dag, name, make(map[string]bool), make(map[string]bool)) {
			return nil, fmt.Errorf("dependency cycle detected involving module %q", name)
		}
	}

	return dag, nil
}

func hasCycle(dag *DAG, current string, visited map[string]bool, recStack map[string]bool) bool {
	if recStack[current] {
		return true
	}
	if visited[current] {
		return false
	}

	visited[current] = true
	recStack[current] = true

	node := dag.nodes[current]
	if node != nil {
		for _, reqArtifact := range node.Requires {
			// Find which module produces this artifact
			for depName, depNode := range dag.nodes {
				for _, prod := range depNode.Produces {
					if prod == reqArtifact {
						if hasCycle(dag, depName, visited, recStack) {
							return true
						}
					}
				}
			}
		}
	}

	recStack[current] = false
	return false
}

// NextReady returns all modules whose dependencies are satisfied and haven't run yet.
func (d *DAG) NextReady(completed map[string]bool, availableArtifacts map[string]bool) []modules.Module {
	var ready []modules.Module

	for name, node := range d.nodes {
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

		if canRun {
			ready = append(ready, node.Module)
		}
	}

	return ready
}
