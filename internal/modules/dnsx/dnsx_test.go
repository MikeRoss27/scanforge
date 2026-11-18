package dnsx

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

func TestWriteResolvedHostsDeduplicatesJSONL(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "dnsx.jsonl")
	output := filepath.Join(dir, "dnsx.txt")
	data := "{\"host\":\"api.example.com\"}\ninvalid\n{\"host\":\"api.example.com\"}\n{\"host\":\"www.example.com\"}\n"
	if err := os.WriteFile(input, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writeResolvedHosts(input, output); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if want := "api.example.com\nwww.example.com\n"; string(got) != want {
		t.Fatalf("resolved hosts = %q, want %q", got, want)
	}
}

func TestMergeLineFilesDeduplicates(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.jsonl")
	second := filepath.Join(dir, "second.jsonl")
	output := filepath.Join(dir, "merged.jsonl")
	writeFile(t, first, "one\ntwo\n")
	writeFile(t, second, "two\nthree\n")
	if err := mergeLineFiles(output, first, second); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if want := "one\ntwo\nthree\n"; string(got) != want {
		t.Fatalf("merged output = %q, want %q", got, want)
	}
}

type stagedExecutor struct {
	mu       sync.Mutex
	inputs   []string
	firstRun chan struct{}
}

func (e *stagedExecutor) Run(_ context.Context, command runner.Command) (*runner.CommandResult, error) {
	e.mu.Lock()
	e.inputs = append(e.inputs, command.Args[1])
	call := len(e.inputs)
	e.mu.Unlock()
	input, err := os.ReadFile(command.Args[1])
	if err != nil {
		return nil, err
	}
	var output strings.Builder
	for _, host := range strings.Fields(string(input)) {
		output.WriteString(`{"host":"` + host + `"}` + "\n")
	}
	if err := os.WriteFile(command.StdoutFile, []byte(output.String()), 0644); err != nil {
		return nil, err
	}
	if call == 1 {
		close(e.firstRun)
	}
	return &runner.CommandResult{Command: command}, nil
}

func TestRunResolvesPassiveHostsBeforeBruteforceFinishes(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"00_meta", "01_subdomains"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	run := &storage.Run{RootDir: root, MetaDir: filepath.Join(root, "00_meta"), CommandsLog: filepath.Join(root, "00_meta", "commands.log")}
	writeFile(t, run.Path("01_subdomains", "subfinder.txt"), "example.com\napi.example.com\n")
	runCtx := modules.NewRunContext("example.com", "full", false, run)
	runCtx.ExpectArtifact("brute_subdomains")
	if err := runCtx.AddArtifact("subdomains", modules.Artifact{Name: "subdomains", Type: "text", Path: "01_subdomains/subfinder.txt"}); err != nil {
		t.Fatal(err)
	}
	executor := &stagedExecutor{firstRun: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		_, err := New("dnsx").Run(context.Background(), runCtx, executor)
		done <- err
	}()

	select {
	case <-executor.firstRun:
		// Passive input was resolved while the optional producer was pending.
	case <-time.After(time.Second):
		t.Fatal("passive DNS resolution did not start")
	}
	select {
	case err := <-done:
		t.Fatalf("dnsx finished before bruteforce publication: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	writeFile(t, run.Path("01_subdomains", "brute.txt"), "vpn.example.com\n")
	if err := runCtx.AddArtifact("brute_subdomains", modules.Artifact{Name: "brute_subdomains", Type: "text", Path: "01_subdomains/brute.txt"}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	executor.mu.Lock()
	inputs := append([]string(nil), executor.inputs...)
	executor.mu.Unlock()
	if len(inputs) != 2 || inputs[0] != run.Path("01_subdomains", "subfinder.txt") || inputs[1] != run.Path("01_subdomains", "brute.txt") {
		t.Fatalf("dnsx inputs = %v", inputs)
	}
	resolved, err := os.ReadFile(run.Path("01_subdomains", "dnsx.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "example.com\napi.example.com\nvpn.example.com\n"; string(resolved) != want {
		t.Fatalf("resolved hosts = %q, want %q", resolved, want)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
