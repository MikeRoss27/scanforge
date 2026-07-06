package modules

import (
	"fmt"
	"strings"
	"sync"

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
	mu        sync.RWMutex
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
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Artifacts[name] = artifact
}

func (c *RunContext) GetArtifact(name string) (Artifact, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	art, ok := c.Artifacts[name]
	return art, ok
}

func (c *RunContext) MustArtifact(name string) (Artifact, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if art, ok := c.Artifacts[name]; ok {
		return art, nil
	}
	available := []string{}
	for k := range c.Artifacts {
		available = append(available, k)
	}
	return Artifact{}, fmt.Errorf("required artifact %q not found (available: %s)", name, strings.Join(available, ", "))
}
