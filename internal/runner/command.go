// Package runner abstracts command execution so scans can run for real or in
// dry-run mode without sending any network traffic.
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
