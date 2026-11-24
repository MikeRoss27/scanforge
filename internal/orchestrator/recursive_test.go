package orchestrator

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/discovery"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
	scanScope "github.com/MikeRoss27/scanforge/internal/scope"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

// jsModule publishes a js_secrets artifact revealing one in-scope and one
// out-of-scope host.
type jsModule struct{}

func (jsModule) Name() string           { return "jsmock" }
func (jsModule) Description() string    { return "" }
func (jsModule) Requires() []string     { return nil }
func (jsModule) Produces() []string     { return []string{"js_secrets"} }
func (jsModule) SoftRequires() []string { return nil }
func (jsModule) Run(_ context.Context, rc *modules.RunContext, _ runner.Executor) (*modules.Result, error) {
	body := `{"url":"https://www.example.com/a.js","kind":"internal-host","match":"late.example.com"}` + "\n" +
		`{"url":"https://www.example.com/a.js","kind":"internal-host","match":"evil.org"}` + "\n"
	if err := os.WriteFile(rc.Run.Path("js.jsonl"), []byte(body), 0o644); err != nil {
		return nil, err
	}
	if err := rc.AddArtifact("js_secrets", modules.Artifact{Name: "js_secrets", Type: "jsonl", Path: "js.jsonl"}); err != nil {
		return nil, err
	}
	return &modules.Result{Name: "jsmock", Status: "completed"}, nil
}

type recordingExec struct {
	mu   sync.Mutex
	cmds []string
}

func (r *recordingExec) Run(_ context.Context, c runner.Command) (*runner.CommandResult, error) {
	r.mu.Lock()
	r.cmds = append(r.cmds, c.Name+" "+strings.Join(c.Args, " "))
	r.mu.Unlock()
	if c.StdoutFile != "" {
		_ = os.WriteFile(c.StdoutFile, nil, 0o644)
	}
	return &runner.CommandResult{Command: c}, nil
}

func runRecursive(t *testing.T, recursive bool) (*recordingExec, *storage.Run) {
	t.Helper()
	run, err := storage.NewRunStore(t.TempDir()).Create("example.com")
	if err != nil {
		t.Fatal(err)
	}
	sc, err := scanScope.FromTarget("example.com", scanScope.ModeDomain, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	reg := modules.NewRegistry()
	reg.Register(jsModule{})
	cfg := config.Default()
	cfg.Profiles["t"] = []string{"jsmock"}
	exec := &recordingExec{}
	ch := make(chan Event, 256)
	_, err = New(exec, reg).Run(context.Background(), run, Options{
		Target: "example.com", Profile: "t", Config: cfg, Scope: sc,
		Recursive: recursive, RecursiveOptions: discovery.Options{Budget: 10},
	}, ch)
	if err != nil {
		t.Fatal(err)
	}
	for e := range ch {
		if w, ok := e.(WarningEvent); ok {
			t.Log(w.Message)
		}
	}
	return exec, run
}

func TestRecursiveOffRunsNoFollowUps(t *testing.T) {
	exec, run := runRecursive(t, false)
	if len(exec.cmds) != 0 {
		t.Fatalf("recursive off must not run commands: %v", exec.cmds)
	}
	if _, err := os.Stat(run.Path("00_meta", "events.jsonl")); err == nil {
		t.Fatal("recursive off must not create events.jsonl")
	}
}

func TestRecursiveOnProbesOnlyInScopeLateHosts(t *testing.T) {
	exec, run := runRecursive(t, true)
	joined := strings.Join(exec.cmds, "\n")
	if len(exec.cmds) == 0 || strings.Contains(joined, "evil.org") {
		t.Fatalf("cmds = %v", exec.cmds)
	}
	rej, _ := os.ReadFile(run.Path("00_meta", "scope-rejections.jsonl"))
	if !strings.Contains(string(rej), "evil.org") {
		t.Fatalf("rejection not logged: %s", rej)
	}
}
