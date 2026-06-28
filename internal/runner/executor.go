package runner

import "context"

type Executor interface {
	Run(ctx context.Context, command Command) (*CommandResult, error)
}
