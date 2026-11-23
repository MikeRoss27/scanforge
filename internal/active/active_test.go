package active

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/app"
)

type fakeProc struct {
	done        chan struct{}
	once        sync.Once
	interrupted bool
}

func (p *fakeProc) PID() int { return 4242 }
func (p *fakeProc) Interrupt() error {
	p.interrupted = true
	p.once.Do(func() { close(p.done) })
	return nil
}
func (p *fakeProc) Kill() error { p.once.Do(func() { close(p.done) }); return nil }
func (p *fakeProc) Wait() error { <-p.done; return nil }

type fakeLauncher struct {
	calls [][]string
	proc  *fakeProc
}

func (l *fakeLauncher) Start(args []string, _ string) (Proc, error) {
	l.calls = append(l.calls, args)
	l.proc = &fakeProc{done: make(chan struct{})}
	return l.proc, nil
}

func newCtl(t *testing.T, allow bool) (*Controller, *fakeLauncher, string) {
	t.Helper()
	dir := t.TempDir()
	scope := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(scope, []byte("example.com\n*.example.com\n!admin.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	audit := filepath.Join(dir, "audit.jsonl")
	l := &fakeLauncher{}
	cfg := Config{Allow: allow, AuditPath: audit, Actor: "test"}
	if allow {
		cfg.ScopeFile = scope
	}
	c, err := New(cfg, l, func(app.PlanOptions) ([]*app.PlanResult, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	return c, l, audit
}

func TestActiveDisabledByDefault(t *testing.T) {
	c, l, _ := newCtl(t, false)
	if _, err := c.Start(StartRequest{Target: "example.com"}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("start err = %v", err)
	}
	if _, err := c.Stop("abc"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("stop err = %v", err)
	}
	if len(l.calls) != 0 {
		t.Fatal("nothing must be launched")
	}
}

func TestAllowActiveRequiresExplicitScope(t *testing.T) {
	if _, err := New(Config{Allow: true, AuditPath: "x"}, &fakeLauncher{}, nil); err == nil {
		t.Fatal("allow without scope file must fail")
	}
	empty := filepath.Join(t.TempDir(), "s.txt")
	_ = os.WriteFile(empty, []byte("# nothing\n"), 0o644)
	if _, err := New(Config{Allow: true, ScopeFile: empty, AuditPath: "x"}, &fakeLauncher{}, nil); err == nil {
		t.Fatal("empty scope must fail")
	}
}

func TestOutOfScopeAndInvalidTargetsRejectedAndAudited(t *testing.T) {
	c, l, audit := newCtl(t, true)
	for _, target := range []string{"evil.com", "admin.example.com", "notexample.com", "--scope=/dev/null", "example.com; rm -rf /", ""} {
		if _, err := c.Start(StartRequest{Target: target}); err == nil {
			t.Errorf("target %q must be rejected", target)
		}
	}
	if _, err := c.Start(StartRequest{Target: "evil.com"}); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("want ErrOutOfScope, got %v", err)
	}
	if len(l.calls) != 0 {
		t.Fatal("nothing must be launched")
	}
	data, _ := os.ReadFile(audit)
	if !strings.Contains(string(data), `"decision":"denied"`) || !strings.Contains(string(data), "evil.com") {
		t.Fatalf("denials must be audited: %s", data)
	}
}

func TestStartAndStopInScope(t *testing.T) {
	c, l, audit := newCtl(t, true)
	info, err := c.Start(StartRequest{Target: "www.example.com", Profile: "web", DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Join(l.calls[0], " ")
	if !strings.Contains(args, "run --scope ") || !strings.Contains(args, "--profile web --dry-run -- www.example.com") {
		t.Fatalf("args: %s", args)
	}
	if strings.Contains(args, "--confirm-scope") || strings.Contains(args, "--scope-mode") || strings.Contains(args, "-H") {
		t.Fatalf("forbidden flags in %s", args)
	}
	if _, err := c.Stop("nope"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("stop unknown: %v", err)
	}
	if _, err := c.Stop(info.ScanID); err != nil {
		t.Fatal(err)
	}
	if !l.proc.interrupted {
		t.Fatal("expected graceful interrupt")
	}
	data, _ := os.ReadFile(audit)
	for _, want := range []string{"start_authorized_scan", "stop_scan", `"decision":"allowed"`, `"actor":"test"`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("audit missing %q: %s", want, data)
		}
	}
}
