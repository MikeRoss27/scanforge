package runner

import "time"

type Command struct {
	Name       string
	Args       []string
	Dir        string
	Env        []string
	StdoutFile string
	StderrFile string
	Timeout    time.Duration
}

type CommandResult struct {
	Command  Command
	ExitCode int
	Duration time.Duration
}
