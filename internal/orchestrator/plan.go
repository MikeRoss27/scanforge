package orchestrator

import "github.com/MikeRoss27/scanforge/internal/modules"

type PlanStep struct {
	Wave        int
	Name        string
	Description string
	Requires    []string
	Produces    []string
}

// batchWave labels a dispatched batch with the lowest static DAG level among
// its modules. Execution is not level-synchronized, so a batch can mix levels;
// labelling it by an arbitrary member (e.g. the first ready one) made the live
// header print wave 6 before wave 5.
func batchWave(names []string, waveByModule map[string]int) int {
	wave := 0
	for _, name := range names {
		if w := waveByModule[name]; w > 0 && (wave == 0 || w < wave) {
			wave = w
		}
	}
	return wave
}

func BuildPlan(selected []modules.Module) ([]PlanStep, error) {
	dag, err := BuildDAG(selected)
	if err != nil {
		return nil, err
	}
	completed := make(map[string]bool)
	available := make(map[string]bool)
	steps := make([]PlanStep, 0, len(selected))
	for wave := 1; len(completed) < len(selected); wave++ {
		ready := dag.NextReady(completed, available)
		for _, module := range ready {
			steps = append(steps, PlanStep{
				Wave: wave, Name: module.Name(), Description: module.Description(),
				Requires: module.Requires(), Produces: module.Produces(),
			})
			completed[module.Name()] = true
			for _, artifact := range module.Produces() {
				available[artifact] = true
			}
		}
	}
	return steps, nil
}
