package orchestrator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
	scanScope "github.com/MikeRoss27/scanforge/internal/scope"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

// fileModule writes a real output file so checkpoints can hash and verify it,
// and counts its executions across runs through a shared counter.
type fileModule struct {
	name     string
	requires []string
	produces string
	content  string
	failOnce *bool
	counter  *runCounter
	// ghost is an output file declared but never written.
	ghost string
}

type runCounter struct {
	mu sync.Mutex
	n  map[string]int
}

func newCounter() *runCounter { return &runCounter{n: map[string]int{}} }
func (c *runCounter) inc(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n[name]++
}
func (c *runCounter) get(name string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n[name]
}

func (m *fileModule) Name() string        { return m.name }
func (m *fileModule) Description() string { return "" }
func (m *fileModule) Requires() []string  { return m.requires }
func (m *fileModule) Produces() []string  { return []string{m.produces} }
func (m *fileModule) Run(ctx context.Context, runCtx *modules.RunContext, _ runner.Executor) (*modules.Result, error) {
	m.counter.inc(m.name)
	if m.failOnce != nil && *m.failOnce {
		*m.failOnce = false
		return &modules.Result{Name: m.name, Status: "failed"}, errors.New("simulated interruption")
	}
	rel := filepath.Join("01_subdomains", m.produces+".txt")
	if err := os.WriteFile(runCtx.Run.Path(rel), []byte(m.content), 0o644); err != nil {
		return nil, err
	}
	if err := runCtx.AddArtifact(m.produces, modules.Artifact{Name: m.produces, Type: "test", Path: rel}); err != nil {
		return nil, err
	}
	outputs := map[string]string{m.produces: rel}
	if m.ghost != "" {
		outputs["ghost"] = m.ghost
	}
	return &modules.Result{Name: m.name, Status: "completed", OutputFiles: outputs}, nil
}

type pipeline struct {
	counter *runCounter
	// aContent/bFail drive the three-module chain a -> b -> c.
	aContent string
	bFail    *bool
}

func (p pipeline) registry() *modules.Registry {
	reg := modules.NewRegistry()
	reg.Register(&fileModule{name: "a", produces: "art_a", content: p.aContent, counter: p.counter})
	reg.Register(&fileModule{name: "b", requires: []string{"art_a"}, produces: "art_b", content: "b-out", failOnce: p.bFail, counter: p.counter})
	reg.Register(&fileModule{name: "c", requires: []string{"art_b"}, produces: "art_c", content: "c-out", counter: p.counter})
	return reg
}

func runPipeline(t *testing.T, ctx context.Context, run *storage.Run, reg *modules.Registry, opts Options) ([]*modules.Result, error) {
	t.Helper()
	cfg := config.Default()
	cfg.Profiles["chain"] = []string{"a", "b", "c"}
	opts.Target, opts.Profile, opts.Config = "example.com", "chain", cfg
	if opts.Scope == nil {
		sc, err := scanScope.FromTarget("example.com", scanScope.ModeExact, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		opts.Scope = sc
	}
	events := make(chan Event, 64)
	done := make(chan struct{})
	go func() {
		for range events {
		}
		close(done)
	}()
	res, err := New(runner.NewDryRunExecutor(false), reg).Run(ctx, run, opts, events)
	<-done
	return res, err
}

func newRun(t *testing.T) *storage.Run {
	t.Helper()
	run, err := storage.NewRunStore(t.TempDir()).Create("example.com")
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func reopen(t *testing.T, run *storage.Run) *storage.Run {
	t.Helper()
	reopened, err := storage.OpenRun(run.RootDir)
	if err != nil {
		t.Fatal(err)
	}
	return reopened
}

func statusOf(t *testing.T, run *storage.Run, name string) string {
	t.Helper()
	rec, ok := run.Module(name)
	if !ok {
		t.Fatalf("no checkpoint for %q", name)
	}
	return rec.Status
}

func TestResumeAfterInterruptionSkipsCompletedModules(t *testing.T) {
	counter := newCounter()
	fail := true
	p := pipeline{counter: counter, aContent: "a-out", bFail: &fail}
	run := newRun(t)

	// First run: b fails, so c is skipped (simulated interruption).
	if _, err := runPipeline(t, context.Background(), run, p.registry(), Options{}); err == nil {
		t.Fatal("first run should fail")
	}
	run = reopen(t, run)
	for name, want := range map[string]string{"a": "completed", "b": "failed", "c": "skipped"} {
		if got := statusOf(t, run, name); got != want {
			t.Errorf("after interruption %s = %q, want %q", name, got, want)
		}
	}

	// Resume: only b and c execute.
	results, err := runPipeline(t, context.Background(), run, p.registry(), Options{Resume: true})
	if err != nil {
		t.Fatalf("resume error = %v", err)
	}
	if counter.get("a") != 1 || counter.get("b") != 2 || counter.get("c") != 1 {
		t.Fatalf("executions a=%d b=%d c=%d, want 1/2/1", counter.get("a"), counter.get("b"), counter.get("c"))
	}
	for _, r := range results {
		if r.Status != "completed" {
			t.Errorf("%s status = %q", r.Name, r.Status)
		}
	}

	// A further resume reuses everything.
	run = reopen(t, run)
	if _, err := runPipeline(t, context.Background(), run, p.registry(), Options{Resume: true}); err != nil {
		t.Fatal(err)
	}
	if counter.get("a") != 1 || counter.get("b") != 2 || counter.get("c") != 1 {
		t.Fatalf("fully checkpointed resume re-ran modules: a=%d b=%d c=%d", counter.get("a"), counter.get("b"), counter.get("c"))
	}
}

func TestResumeRerunsNonCompletedStates(t *testing.T) {
	for _, state := range []string{storage.ModuleRunning, storage.ModuleFailed, storage.ModuleCancelled, storage.ModulePending, storage.ModuleSkipped} {
		t.Run(state, func(t *testing.T) {
			counter := newCounter()
			p := pipeline{counter: counter, aContent: "a-out"}
			run := newRun(t)
			if _, err := runPipeline(t, context.Background(), run, p.registry(), Options{}); err != nil {
				t.Fatal(err)
			}
			// Simulate the process dying while "b" was in this state.
			run = reopen(t, run)
			rec, _ := run.Module("b")
			rec.Status = state
			if err := run.UpdateModule(rec); err != nil {
				t.Fatal(err)
			}
			run = reopen(t, run)
			if _, err := runPipeline(t, context.Background(), run, p.registry(), Options{Resume: true}); err != nil {
				t.Fatal(err)
			}
			if counter.get("a") != 1 || counter.get("b") != 2 {
				t.Fatalf("a=%d b=%d, want a reused and b re-run", counter.get("a"), counter.get("b"))
			}
			// c's input (b's output) is byte-identical, so it stays cached.
			if counter.get("c") != 1 {
				t.Fatalf("c=%d, want 1 (unchanged input)", counter.get("c"))
			}
		})
	}
}

func TestResumeInvalidatesChangedInputs(t *testing.T) {
	otherScope, err := scanScope.FromTarget("other.com", scanScope.ModeExact, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		aContent string
		opts     Options
		tamper   func(t *testing.T, run *storage.Run)
		wantA    int
		wantB    int
		wantC    int
	}{
		{name: "nothing changed", aContent: "a-out", wantA: 1, wantB: 1, wantC: 1},
		{name: "scope changed", aContent: "a-out", opts: Options{Scope: otherScope}, wantA: 2, wantB: 2, wantC: 2},
		{name: "proxy changed", aContent: "a-out", opts: Options{Proxy: "http://127.0.0.1:8080"}, wantA: 2, wantB: 2, wantC: 2},
		{name: "headers changed", aContent: "a-out", opts: Options{Headers: []string{"Cookie: x=1"}}, wantA: 2, wantB: 2, wantC: 2},
		{name: "tool version changed", aContent: "a-out", opts: Options{ToolVersion: func(string) string { return "v2" }}, wantA: 2, wantB: 2, wantC: 2},
		{name: "unrelated tool option ignored", aContent: "a-out", opts: Options{NmapConcurrency: 9}, wantA: 1, wantB: 1, wantC: 1},
		{
			name: "upstream artifact tampered", aContent: "a-out",
			tamper: func(t *testing.T, run *storage.Run) {
				if err := os.WriteFile(run.Path("01_subdomains", "art_a.txt"), []byte("changed"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			// a's own inputs are unchanged and its output still exists, so
			// it is reused; b sees different required content and re-runs.
			wantA: 1, wantB: 2, wantC: 1,
		},
		{
			name: "output artifact deleted", aContent: "a-out",
			tamper: func(t *testing.T, run *storage.Run) {
				if err := os.Remove(run.Path("01_subdomains", "art_b.txt")); err != nil {
					t.Fatal(err)
				}
			},
			wantA: 1, wantB: 2, wantC: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			counter := newCounter()
			p := pipeline{counter: counter, aContent: tt.aContent}
			run := newRun(t)
			if _, err := runPipeline(t, context.Background(), run, p.registry(), Options{ToolVersion: func(string) string { return "v1" }}); err != nil {
				t.Fatal(err)
			}
			if tt.tamper != nil {
				tt.tamper(t, run)
			}
			run = reopen(t, run)
			opts := tt.opts
			opts.Resume = true
			if opts.ToolVersion == nil {
				opts.ToolVersion = func(string) string { return "v1" }
			}
			if _, err := runPipeline(t, context.Background(), run, p.registry(), opts); err != nil {
				t.Fatal(err)
			}
			if counter.get("a") != tt.wantA || counter.get("b") != tt.wantB || counter.get("c") != tt.wantC {
				t.Fatalf("executions a=%d b=%d c=%d, want %d/%d/%d",
					counter.get("a"), counter.get("b"), counter.get("c"), tt.wantA, tt.wantB, tt.wantC)
			}
		})
	}
}

func TestResumeCancelledRunKeepsCompletedWork(t *testing.T) {
	counter := newCounter()
	p := pipeline{counter: counter, aContent: "a-out"}
	run := newRun(t)

	ctx, cancel := context.WithCancel(context.Background())
	aborting := modules.NewRegistry()
	aborting.Register(&cancelAfterFile{fileModule: fileModule{name: "a", produces: "art_a", content: "a-out", counter: counter}, cancel: cancel})
	aborting.Register(&fileModule{name: "b", requires: []string{"art_a"}, produces: "art_b", content: "b-out", counter: counter})
	aborting.Register(&fileModule{name: "c", requires: []string{"art_b"}, produces: "art_c", content: "c-out", counter: counter})
	if _, err := runPipeline(t, ctx, run, aborting, Options{}); !errors.Is(err, ErrRunAborted) {
		t.Fatalf("expected abort, got %v", err)
	}
	run = reopen(t, run)
	if got := statusOf(t, run, "a"); got != storage.ModuleCompleted {
		t.Errorf("a = %q", got)
	}
	if got := statusOf(t, run, "b"); got != storage.ModuleCancelled {
		t.Errorf("b = %q, want cancelled", got)
	}

	if _, err := runPipeline(t, context.Background(), run, p.registry(), Options{Resume: true}); err != nil {
		t.Fatal(err)
	}
	if counter.get("a") != 1 || counter.get("b") != 1 || counter.get("c") != 1 {
		t.Fatalf("a=%d b=%d c=%d, want each once in total", counter.get("a"), counter.get("b"), counter.get("c"))
	}
}

type cancelAfterFile struct {
	fileModule
	cancel context.CancelFunc
}

func (m *cancelAfterFile) Run(ctx context.Context, runCtx *modules.RunContext, ex runner.Executor) (*modules.Result, error) {
	res, err := m.fileModule.Run(ctx, runCtx, ex)
	m.cancel()
	return res, err
}

func TestResumeRescopesRestoredArtifacts(t *testing.T) {
	// A restored scoped artifact is filtered again: a widened file content
	// (tampered after the original run) cannot leak out-of-scope hosts to
	// downstream modules.
	counter := newCounter()
	reg := modules.NewRegistry()
	reg.Register(&scopedProducer{counter: counter})
	reg.Register(&fileModule{name: "b", requires: []string{"resolved_hosts"}, produces: "art_b", content: "b", counter: counter})
	cfg := config.Default()
	cfg.Profiles["scoped"] = []string{"hosts", "b"}
	run := newRun(t)
	sc, err := scanScope.FromTarget("example.com", scanScope.ModeDomain, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{Target: "example.com", Profile: "scoped", Config: cfg, Scope: sc}
	drain := func(o Options) {
		events := make(chan Event, 64)
		go func() {
			for range events {
			}
		}()
		if _, err := New(runner.NewDryRunExecutor(false), reg).Run(context.Background(), run, o, events); err != nil {
			t.Fatal(err)
		}
	}
	drain(opts)
	path := run.Path("01_subdomains", "resolved_hosts.txt")
	if err := os.WriteFile(path, []byte("a.example.com\nevil.org\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run = reopen(t, run)
	opts.Resume = true
	drain(opts)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "evil.org") {
		t.Fatalf("restored artifact was not re-filtered against scope: %q", data)
	}
}

type scopedProducer struct{ counter *runCounter }

func (m *scopedProducer) Name() string        { return "hosts" }
func (m *scopedProducer) Description() string { return "" }
func (m *scopedProducer) Requires() []string  { return nil }
func (m *scopedProducer) Produces() []string  { return []string{"resolved_hosts"} }
func (m *scopedProducer) Run(_ context.Context, runCtx *modules.RunContext, _ runner.Executor) (*modules.Result, error) {
	m.counter.inc("hosts")
	rel := filepath.Join("01_subdomains", "resolved_hosts.txt")
	if err := os.WriteFile(runCtx.Run.Path(rel), []byte("a.example.com\n"), 0o644); err != nil {
		return nil, err
	}
	if err := runCtx.AddArtifact("resolved_hosts", modules.Artifact{Name: "resolved_hosts", Type: "text", Path: rel}); err != nil {
		return nil, err
	}
	return &modules.Result{Name: "hosts", Status: "completed"}, nil
}

func TestManifestWrittenAtomicallyOnEveryStateChange(t *testing.T) {
	counter := newCounter()
	p := pipeline{counter: counter, aContent: "a-out"}
	run := newRun(t)
	if _, err := runPipeline(t, context.Background(), run, p.registry(), Options{}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(run.MetaDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("leftover temp file %s", e.Name())
		}
	}
	reopened := reopen(t, run)
	rec, ok := reopened.Module("b")
	if !ok || rec.Status != storage.ModuleCompleted || rec.InputHash == "" || rec.Artifacts["art_b"].Path == "" {
		t.Fatalf("incomplete checkpoint for b: %+v", rec)
	}
}

// A module may declare an output file it never wrote (e.g. dnsx_stderr when
// every input is an IP literal). That must not make its checkpoint look
// damaged and force a re-run on every resume.
func TestResumeReusesModuleWithUnwrittenDeclaredOutput(t *testing.T) {
	counter := newCounter()
	reg := modules.NewRegistry()
	reg.Register(&fileModule{name: "a", produces: "art_a", content: "a-out", counter: counter, ghost: "00_meta/a.stderr.log"})
	reg.Register(&fileModule{name: "b", requires: []string{"art_a"}, produces: "art_b", content: "b-out", counter: counter})
	reg.Register(&fileModule{name: "c", requires: []string{"art_b"}, produces: "art_c", content: "c-out", counter: counter})
	run := newRun(t)
	if _, err := runPipeline(t, context.Background(), run, reg, Options{}); err != nil {
		t.Fatal(err)
	}
	run = reopen(t, run)
	if _, err := runPipeline(t, context.Background(), run, reg, Options{Resume: true}); err != nil {
		t.Fatal(err)
	}
	if counter.get("a") != 1 {
		t.Fatalf("module with an unwritten declared output re-ran on resume: a=%d", counter.get("a"))
	}
}
