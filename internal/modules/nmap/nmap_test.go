package nmap

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

// recordingExecutor is shared across concurrent nmap goroutines (the module
// now runs one host per worker), so appends must be synchronized.
type recordingExecutor struct {
	mu       sync.Mutex
	commands []runner.Command
}

func (e *recordingExecutor) Run(_ context.Context, command runner.Command) (*runner.CommandResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.commands = append(e.commands, command)
	return &runner.CommandResult{Command: command, ExitCode: 0}, nil
}

// commandForHost returns the recorded command targeting host. Commands run
// concurrently, so callers must look them up by host rather than by index.
func (e *recordingExecutor) commandForHost(t *testing.T, host string) runner.Command {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, cmd := range e.commands {
		if len(cmd.Args) > 0 && cmd.Args[len(cmd.Args)-1] == host {
			return cmd
		}
	}
	t.Fatalf("no recorded command for host %q (commands: %v)", host, e.commands)
	return runner.Command{}
}

func TestRequiresOpenPorts(t *testing.T) {
	if got, want := New("").Requires(), []string{"open_ports"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Requires() = %v, want %v", got, want)
	}
}

func TestRunBuildsOnePortRestrictedCommandPerHost(t *testing.T) {
	root := t.TempDir()
	run := testRun(t, root)
	naabuPath := run.Path("03_ports", "naabu.txt")
	content := strings.Join([]string{
		"beta.example.com:443",
		"alpha.example.com:8080",
		"alpha.example.com:80",
		"alpha.example.com:80",
	}, "\n")
	if err := os.WriteFile(naabuPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	runCtx := modules.NewRunContext("example.com", "ports", false, run)
	runCtx.AddArtifact("open_ports", modules.Artifact{
		Name: "open_ports",
		Type: "text",
		Path: "03_ports/naabu.txt",
	})
	executor := &recordingExecutor{}

	result, err := New("nmap-test").Run(context.Background(), runCtx, executor)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("Run() status = %q, want completed", result.Status)
	}
	if len(executor.commands) != 2 {
		t.Fatalf("command count = %d, want 2", len(executor.commands))
	}

	assertCommandTarget(t, executor.commandForHost(t, "alpha.example.com"), "alpha.example.com", "80,8080")
	assertCommandTarget(t, executor.commandForHost(t, "beta.example.com"), "beta.example.com", "443")
}

func TestRunSupportsBracketedIPv6(t *testing.T) {
	root := t.TempDir()
	run := testRun(t, root)
	if err := os.WriteFile(run.Path("03_ports", "naabu.txt"), []byte("[2001:db8::1]:443\n"), 0644); err != nil {
		t.Fatal(err)
	}

	runCtx := modules.NewRunContext("2001:db8::1", "ports", false, run)
	runCtx.AddArtifact("open_ports", modules.Artifact{Path: "03_ports/naabu.txt"})
	executor := &recordingExecutor{}

	if _, err := New("nmap-test").Run(context.Background(), runCtx, executor); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(executor.commands) != 1 {
		t.Fatalf("command count = %d, want 1", len(executor.commands))
	}
	if !contains(executor.commands[0].Args, "-6") {
		t.Fatalf("command args = %v, want IPv6 flag", executor.commands[0].Args)
	}
	assertCommandTarget(t, executor.commands[0], "2001:db8::1", "443")
}

func TestParseHostPortRejectsInvalidPort(t *testing.T) {
	if _, _, err := parseHostPort("example.com:70000"); err == nil {
		t.Fatal("parseHostPort() expected an invalid port error")
	}
}

func testRun(t *testing.T, root string) *storage.Run {
	t.Helper()
	for _, dir := range []string{"00_meta", "03_ports"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	return &storage.Run{
		RootDir:     root,
		CommandsLog: filepath.Join(root, "00_meta", "commands.log"),
	}
}

func assertCommandTarget(t *testing.T, command runner.Command, host, ports string) {
	t.Helper()
	if command.Name != "nmap-test" {
		t.Fatalf("command name = %q, want nmap-test", command.Name)
	}
	if contains(command.Args, "-iL") {
		t.Fatalf("command args = %v, must not pass naabu output to -iL", command.Args)
	}
	portIndex := index(command.Args, "-p")
	if portIndex < 0 || portIndex+1 >= len(command.Args) || command.Args[portIndex+1] != ports {
		t.Fatalf("command args = %v, want -p %s", command.Args, ports)
	}
	if got := command.Args[len(command.Args)-1]; got != host {
		t.Fatalf("last command argument = %q, want host %q", got, host)
	}
}

func contains(values []string, value string) bool {
	return index(values, value) >= 0
}

func index(values []string, value string) int {
	for i, candidate := range values {
		if reflect.DeepEqual(candidate, value) {
			return i
		}
	}
	return -1
}
