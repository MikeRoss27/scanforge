package modules

import (
	"context"

	"github.com/MikeRoss27/scanforge/internal/runner"
)

type Result struct {
	Name        string
	Status      string
	OutputFiles map[string]string
}

type Module interface {
	Name() string
	Description() string
	Requires() []string
	Produces() []string
	Run(ctx context.Context, runCtx *RunContext, executor runner.Executor) (*Result, error)
}

// SoftRequires is an optional Module extension. Artifacts listed here should
// be produced before the module runs when their producer is part of the
// profile, but — unlike Requires — a missing producer is not a build error:
// the module reads those upstreams conditionally at runtime.
type SoftRequires interface {
	SoftRequires() []string
}
