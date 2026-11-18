package runner

import "context"

type Executor interface {
	Run(ctx context.Context, command Command) (*CommandResult, error)
}

// CommandSink receives every executed command with its result and error.
// It is optional diagnostics plumbing (used by -vv to echo commands);
// install it with WithCommandSink. It must be safe for concurrent use
// because modules run concurrently within a wave.
type CommandSink func(command Command, result *CommandResult, err error)

// ExecutorOption configures optional executor behavior.
type ExecutorOption func(*executorOptions)

type executorOptions struct {
	commandSink CommandSink
}

// WithCommandSink installs the diagnostics hook invoked after each command.
func WithCommandSink(sink CommandSink) ExecutorOption {
	return func(o *executorOptions) { o.commandSink = sink }
}

func applyOptions(opts []ExecutorOption) executorOptions {
	var cfg executorOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
}
