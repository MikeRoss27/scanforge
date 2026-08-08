package nmap

import (
	"context"
	"fmt"
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
	if err := runCtx.AddArtifact("open_ports", modules.Artifact{
		Name: "open_ports",
		Type: "text",
		Path: "03_ports/naabu.txt",
	}); err != nil {
		t.Fatal(err)
	}
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
	if err := runCtx.AddArtifact("open_ports", modules.Artifact{Path: "03_ports/naabu.txt"}); err != nil {
		t.Fatal(err)
	}
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

func TestChunkPortsSplitsOversizedLists(t *testing.T) {
	ports := make([]int, 0, 600)
	for i := 1; i <= 600; i++ {
		ports = append(ports, i)
	}
	chunks := chunkPorts(ports)
	if len(chunks) != 3 {
		t.Fatalf("chunkPorts(600) = %d chunks, want 3", len(chunks))
	}
	if len(chunks[0]) != maxPortsPerCommand || len(chunks[1]) != maxPortsPerCommand || len(chunks[2]) != 100 {
		t.Fatalf("chunk sizes = %d/%d/%d, want 250/250/100", len(chunks[0]), len(chunks[1]), len(chunks[2]))
	}
	if chunks[0][0] != 1 || chunks[1][0] != maxPortsPerCommand+1 || chunks[2][0] != 501 {
		t.Fatalf("chunk boundaries wrong: starts = %d/%d/%d", chunks[0][0], chunks[1][0], chunks[2][0])
	}

	if got := chunkPorts([]int{80, 443}); len(got) != 1 || !reflect.DeepEqual(got[0], []int{80, 443}) {
		t.Fatalf("chunkPorts(small) = %v, want single unchanged chunk", got)
	}
}

func TestRunChunksLargePortListsPerHost(t *testing.T) {
	root := t.TempDir()
	run := testRun(t, root)
	naabuPath := run.Path("03_ports", "naabu.txt")
	var lines []string
	for i := 1; i <= 600; i++ {
		lines = append(lines, fmt.Sprintf("alpha.example.com:%d", i))
	}
	if err := os.WriteFile(naabuPath, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	runCtx := modules.NewRunContext("example.com", "ports", false, run)
	if err := runCtx.AddArtifact("open_ports", modules.Artifact{
		Name: "open_ports",
		Type: "text",
		Path: "03_ports/naabu.txt",
	}); err != nil {
		t.Fatal(err)
	}
	executor := &recordingExecutor{}

	if _, err := New("nmap-test").Run(context.Background(), runCtx, executor); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	var alphaCmds []runner.Command
	for _, cmd := range executor.commands {
		if len(cmd.Args) > 0 && cmd.Args[len(cmd.Args)-1] == "alpha.example.com" {
			alphaCmds = append(alphaCmds, cmd)
		}
	}
	if len(alphaCmds) != 3 {
		t.Fatalf("alpha.example.com commands = %d, want 3 chunks; all commands = %v", len(alphaCmds), executor.commands)
	}
	var allPorts []string
	for _, cmd := range alphaCmds {
		portIndex := index(cmd.Args, "-p")
		if portIndex < 0 {
			t.Fatalf("command missing -p: %v", cmd.Args)
		}
		list := strings.Split(cmd.Args[portIndex+1], ",")
		if len(list) > maxPortsPerCommand {
			t.Fatalf("chunk has %d ports, exceeds max %d", len(list), maxPortsPerCommand)
		}
		allPorts = append(allPorts, list...)
	}
	if len(allPorts) != 600 {
		t.Fatalf("total scanned ports = %d, want 600", len(allPorts))
	}
	// Every chunk writes its own XML so no output file is overwritten.
	xmlNames := make(map[string]struct{})
	for _, cmd := range alphaCmds {
		oXIndex := index(cmd.Args, "-oX")
		if oXIndex >= 0 {
			xmlNames[filepath.Base(cmd.Args[oXIndex+1])] = struct{}{}
		}
	}
	if len(xmlNames) != 3 {
		t.Fatalf("distinct XML outputs = %d, want 3: %v", len(xmlNames), xmlNames)
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
