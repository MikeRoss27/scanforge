package modules

import (
	"fmt"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/storage"
)

type Artifact struct {
	Name string
	Type string
	Path string
}

type RunContext struct {
	Target    string
	Profile   string
	DryRun    bool
	Run       *storage.Run
	Artifacts map[string]Artifact
}

func NewRunContext(target, profile string, dryRun bool, run *storage.Run) *RunContext {
	return &RunContext{
		Target:    target,
		Profile:   profile,
		DryRun:    dryRun,
		Run:       run,
		Artifacts: make(map[string]Artifact),
	}
}

func (c *RunContext) AddArtifact(name string, artifact Artifact) {
	c.Artifacts[name] = artifact
}

func (c *RunContext) GetArtifact(name string) (Artifact, bool) {
	art, ok := c.Artifacts[name]
	return art, ok
}

func (c *RunContext) MustArtifact(name string) (Artifact, error) {
	if art, ok := c.Artifacts[name]; ok {
		return art, nil
	}
	available := []string{}
	for k := range c.Artifacts {
		available = append(available, k)
	}
	return Artifact{}, fmt.Errorf("required artifact %q not found (available: %s)", name, strings.Join(available, ", "))
}
