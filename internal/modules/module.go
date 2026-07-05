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
