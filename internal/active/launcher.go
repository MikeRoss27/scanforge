package active

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// Proc is a running child scan.
type Proc interface {
	PID() int
	Interrupt() error
	Kill() error
	Wait() error
}

// Launcher starts `scanforge <args>` (injectable for tests).
type Launcher interface {
	Start(args []string, logFile string) (Proc, error)
}

// ExecLauncher re-executes the current binary. stdout/stderr go to a log
// file (never to our own stdout: MCP speaks JSON-RPC on it) and stdin is
// closed so no interactive prompt can ever approve anything.
type ExecLauncher struct {
	Executable string
}

type execProc struct{ cmd *exec.Cmd }

func (p *execProc) PID() int { return p.cmd.Process.Pid }
func (p *execProc) Interrupt() error {
	if runtime.GOOS == "windows" {
		return p.cmd.Process.Kill()
	}
	return p.cmd.Process.Signal(os.Interrupt)
}
func (p *execProc) Kill() error { return p.cmd.Process.Kill() }
func (p *execProc) Wait() error { return p.cmd.Wait() }

// Start implements Launcher.
func (l ExecLauncher) Start(args []string, logFile string) (Proc, error) {
	exe := l.Executable
	if exe == "" {
		var err error
		if exe, err = os.Executable(); err != nil {
			return nil, err
		}
	}
	cmd := exec.Command(exe, args...)
	cmd.Stdin = nil
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open scan log: %w", err)
		}
		cmd.Stdout, cmd.Stderr = f, f
		defer func() { _ = f.Close() }()
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &execProc{cmd: cmd}, nil
}
