package modules

import (
	"context"

	"github.com/MikeRoss27/scanforge/internal/runner"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

type Result struct {
	Name        string
	OutputFiles map[string]string
}

type Module interface {
	Name() string
	Run(ctx context.Context, scanRun *storage.Run, executor runner.Executor, target string) (*Result, error)
}
