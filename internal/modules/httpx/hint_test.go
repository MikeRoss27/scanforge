package httpx

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
	scanscope "github.com/MikeRoss27/scanforge/internal/scope"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

type captureExecutor struct{ input string }

func (e *captureExecutor) Run(_ context.Context, command runner.Command) (*runner.CommandResult, error) {
	data, err := os.ReadFile(command.Args[1])
	if err != nil {
		return nil, err
	}
	e.input = string(data)
	if err := os.WriteFile(command.StdoutFile, nil, 0o644); err != nil {
		return nil, err
	}
	return &runner.CommandResult{Command: command}, nil
}

// runHint executes httpx for target over resolved hosts and returns the -l
// input the tool was given.
func runHint(t *testing.T, target, resolved string, scopeEntries ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"00_meta", "01_subdomains", "02_http"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	run := &storage.Run{RootDir: root, MetaDir: filepath.Join(root, "00_meta"), CommandsLog: filepath.Join(root, "00_meta", "commands.log")}
	if err := os.WriteFile(run.Path("01_subdomains", "resolved.txt"), []byte(resolved), 0o644); err != nil {
		t.Fatal(err)
	}
	scopeFile := filepath.Join(root, "scope.txt")
	if err := os.WriteFile(scopeFile, []byte(strings.Join(scopeEntries, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	scope, err := scanscope.LoadFromFile(scopeFile)
	if err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext(target, "web", false, run, scope)
	if err := runCtx.AddArtifact("resolved_hosts", modules.Artifact{Name: "resolved_hosts", Type: "text", Path: "01_subdomains/resolved.txt"}); err != nil {
		t.Fatal(err)
	}
	exec := &captureExecutor{}
	if _, err := New("httpx").Run(context.Background(), runCtx, exec); err != nil {
		t.Fatal(err)
	}
	return exec.input
}

func TestTargetPortIsProbedByHttpx(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		resolved string
		scope    []string
		want     string
	}{
		{"url with port", "http://127.0.0.1:8082", "127.0.0.1\n", []string{"127.0.0.1"}, "127.0.0.1\n127.0.0.1:8082\n"},
		{"https url with port", "https://app.example.com:8443/x", "app.example.com\nwww.example.com\n", []string{"*.example.com"}, "app.example.com\nwww.example.com\napp.example.com:8443\n"},
		{"bare host:port", "example.com:8443", "example.com\n", []string{"example.com"}, "example.com\nexample.com:8443\n"},
		{"no port keeps hosts only", "http://127.0.0.1", "127.0.0.1\n", []string{"127.0.0.1"}, "127.0.0.1\n"},
		{"default port is not repeated", "https://example.com:443", "example.com\n", []string{"example.com"}, "example.com\n"},
		{"host out of scope is never probed", "http://evil.test:8082", "127.0.0.1\n", []string{"127.0.0.1"}, "127.0.0.1\n"},
		{"host not resolved is never probed", "http://127.0.0.2:8082", "127.0.0.1\n", []string{"127.0.0.1", "127.0.0.2"}, "127.0.0.1\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := runHint(t, tt.target, tt.resolved, tt.scope...); got != tt.want {
				t.Fatalf("httpx input = %q, want %q", got, tt.want)
			}
		})
	}
}
