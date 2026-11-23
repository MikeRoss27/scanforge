package discovery

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
	scanScope "github.com/MikeRoss27/scanforge/internal/scope"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

// fakeExec simulates dnsx, httpx and katana by writing their StdoutFile. It
// records every command and the content of every input file it was given.
type fakeExec struct {
	mu     sync.Mutex
	cmds   []runner.Command
	inputs []string // names/URLs handed to the tools
	// crawl maps a katana -u URL to the URLs it "finds".
	crawl map[string][]string
	// noResolve names dnsx cannot resolve.
	noResolve map[string]bool
}

func (f *fakeExec) Run(_ context.Context, cmd runner.Command) (*runner.CommandResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds = append(f.cmds, cmd)
	arg := func(flag string) string {
		for i, a := range cmd.Args {
			if a == flag && i+1 < len(cmd.Args) {
				return cmd.Args[i+1]
			}
		}
		return ""
	}
	var out strings.Builder
	switch cmd.Name {
	case "dnsx", "httpx":
		data, err := os.ReadFile(arg("-l"))
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Fields(string(data)) {
			f.inputs = append(f.inputs, line)
			if cmd.Name == "dnsx" && !f.noResolve[line] {
				b, _ := json.Marshal(map[string]string{"host": line})
				out.Write(b)
				out.WriteByte('\n')
			}
			if cmd.Name == "httpx" {
				b, _ := json.Marshal(map[string]string{"url": "http://" + line})
				out.Write(b)
				out.WriteByte('\n')
			}
		}
	case "katana":
		u := arg("-u")
		f.inputs = append(f.inputs, u)
		for _, l := range f.crawl[u] {
			out.WriteString(l + "\n")
		}
	}
	if err := os.WriteFile(cmd.StdoutFile, []byte(out.String()), 0o644); err != nil {
		return nil, err
	}
	return &runner.CommandResult{Command: cmd}, nil
}

func (f *fakeExec) names(tool string) int {
	n := 0
	for _, c := range f.cmds {
		if c.Name == tool {
			n++
		}
	}
	return n
}

func newEnv(t *testing.T, target string, opts Options, x *fakeExec) (*modules.RunContext, *Engine, string) {
	t.Helper()
	root := t.TempDir()
	meta := filepath.Join(root, "00_meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	run := &storage.Run{RootDir: root, MetaDir: meta, CommandsLog: filepath.Join(meta, "commands.log")}
	sc, err := scanScope.FromTarget(target, scanScope.ModeDomain, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rc := modules.NewRunContext(target, "recon", false, run, sc)
	if err := rc.EnableEventsWith(modules.EventsOptions{MaxDepth: opts.Defaults().MaxDepth, Extended: true}); err != nil {
		t.Fatal(err)
	}
	eng, err := New(rc, x, opts)
	if err != nil {
		t.Fatal(err)
	}
	return rc, eng, root
}

func publish(t *testing.T, rc *modules.RunContext, root, name, rel, typ, content string, scoped bool) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := rc.AddArtifact(name, modules.Artifact{Name: name, Type: typ, Path: rel, Scoped: scoped}); err != nil {
		t.Fatal(err)
	}
}

func jsLine(url, kind, match string) string {
	b, _ := json.Marshal(map[string]string{"url": url, "kind": kind, "match": match})
	return string(b) + "\n"
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}

func TestLateDNSNameTriggersResolveProbeThenCrawl(t *testing.T) {
	x := &fakeExec{crawl: map[string][]string{
		"http://late.example.com": {"http://late.example.com/app.js", "http://deeper.example.com/x"},
	}}
	rc, eng, root := newEnv(t, "example.com", Options{}, x)

	// The DAG already knows www; JS reveals late.example.com.
	publish(t, rc, root, "subdomains", "01/subs.txt", "text", "www.example.com\n", true)
	publish(t, rc, root, "js_secrets", "06/js.jsonl", "jsonl",
		jsLine("https://www.example.com/a.js", "internal-host", "late.example.com")+
			jsLine("https://www.example.com/a.js", "internal-host", "www.example.com"), false)

	if err := eng.Process(context.Background()); err != nil {
		t.Fatal(err)
	}
	// late: dnsx+httpx+katana; deeper (found by the crawl): dnsx+httpx; its
	// live URL would need depth 3 for another crawl.
	if got := x.names("dnsx"); got != 2 {
		t.Fatalf("dnsx runs = %d, want 2 (late, deeper); cmds=%v", got, x.cmds)
	}
	if got := x.names("katana"); got != 1 {
		t.Fatalf("katana runs = %d, want 1: %v", got, x.inputs)
	}
	for _, c := range x.cmds {
		if c.Name == "katana" && !strings.Contains(strings.Join(c.Args, " "), "-depth 1") {
			t.Fatalf("katana must run at depth 1: %v", c.Args)
		}
	}
	for _, in := range x.inputs {
		if in == "www.example.com" {
			t.Fatal("name already known by the DAG must not be re-probed")
		}
	}
	events := readFile(t, filepath.Join(root, "00_meta", "events.jsonl"))
	for _, want := range []string{`"type":"JS_URL"`, `"type":"LIVE_URL"`, `"source":"recursive:httpx"`} {
		if !strings.Contains(events, want) {
			t.Fatalf("events.jsonl lacks %s:\n%s", want, events)
		}
	}
	if !strings.Contains(readFile(t, rc.Run.CommandsLog), "katana") {
		t.Fatal("follow-ups must be written to commands.log")
	}
}

func TestOutOfScopeJSDiscoveriesAreNeverProbed(t *testing.T) {
	x := &fakeExec{crawl: map[string][]string{}}
	rc, eng, root := newEnv(t, "example.com", Options{}, x)
	publish(t, rc, root, "js_secrets", "06/js.jsonl", "jsonl",
		jsLine("https://www.example.com/a.js", "internal-host", "evil.org")+
			jsLine("https://www.example.com/a.js", "cloud-storage", "storage.googleapis.com/bucket")+
			jsLine("https://www.example.com/a.js", "endpoint", "https://evil.org/api/v1")+
			jsLine("https://evil.org/b.js", "endpoint", "/api/users")+
			jsLine("https://www.example.com/a.js", "endpoint", "/api/users"), false)
	if err := eng.Process(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(x.cmds) != 0 {
		t.Fatalf("no command may run for out-of-scope or non-actionable events: %v", x.cmds)
	}
	rej := readFile(t, filepath.Join(root, "00_meta", "scope-rejections.jsonl"))
	for _, want := range []string{"evil.org", "storage.googleapis.com", "https://evil.org/api/v1"} {
		if !strings.Contains(rej, want) {
			t.Fatalf("rejection log lacks %q:\n%s", want, rej)
		}
	}
	events := readFile(t, filepath.Join(root, "00_meta", "events.jsonl"))
	if strings.Contains(events, "evil.org") {
		t.Fatalf("out-of-scope value leaked into accepted events:\n%s", events)
	}
	// The relative route of the in-scope JS is accepted, absolute, with its
	// host as ScopeRef; the one served by evil.org is not.
	if !strings.Contains(events, `"value":"https://www.example.com/api/users"`) ||
		!strings.Contains(events, `"scope_ref":"https://www.example.com"`) {
		t.Fatalf("relative API_ROUTE must carry its host as scope_ref:\n%s", events)
	}
}

func TestCrawlResultsOutOfScopeAreFilteredAndNotProbed(t *testing.T) {
	x := &fakeExec{crawl: map[string][]string{
		"http://late.example.com": {"http://evil.org/x.js", "http://late.example.com/y"},
	}}
	rc, eng, root := newEnv(t, "example.com", Options{}, x)
	publish(t, rc, root, "js_secrets", "06/js.jsonl", "jsonl", jsLine("https://www.example.com/a.js", "internal-host", "late.example.com"), false)
	if err := eng.Process(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, in := range x.inputs {
		if strings.Contains(in, "evil.org") {
			t.Fatalf("out-of-scope URL reached a tool: %q", in)
		}
	}
	if !strings.Contains(readFile(t, filepath.Join(root, "00_meta", "scope-rejections.jsonl")), "evil.org") {
		t.Fatal("crawl rejection must be logged")
	}
}

func TestLoopsTerminate(t *testing.T) {
	// a -> crawl finds b; b -> crawl finds a again (cycle).
	x := &fakeExec{crawl: map[string][]string{
		"http://a.example.com": {"http://b.example.com/"},
		"http://b.example.com": {"http://a.example.com/"},
	}}
	rc, eng, root := newEnv(t, "example.com", Options{MaxDepth: 50, Budget: 1000}, x)
	publish(t, rc, root, "js_secrets", "06/js.jsonl", "jsonl", jsLine("https://www.example.com/a.js", "internal-host", "a.example.com"), false)
	if err := eng.Process(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := x.names("dnsx"); got != 2 {
		t.Fatalf("each name must be resolved once, got %d", got)
	}
	if got := x.names("katana"); got != 2 {
		t.Fatalf("each live URL must be crawled once, got %d", got)
	}
}

func TestDepthLimitStopsChain(t *testing.T) {
	// late(d0) -> live(d1) -> crawl finds c(d2) -> live(d3) -> crawl finds d(d4)
	x := &fakeExec{crawl: map[string][]string{
		"http://late.example.com": {"http://c.example.com/"},
		"http://c.example.com":    {"http://d.example.com/"},
	}}
	for depth, wantDNSX := range map[int]int{1: 1, 2: 2, 3: 2, 4: 3} {
		x.cmds, x.inputs = nil, nil
		rc, eng, root := newEnv(t, "example.com", Options{MaxDepth: depth}, x)
		publish(t, rc, root, "js_secrets", "06/js.jsonl", "jsonl", jsLine("https://www.example.com/a.js", "internal-host", "late.example.com"), false)
		if err := eng.Process(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := x.names("dnsx"); got != wantDNSX {
			t.Fatalf("depth %d: dnsx runs = %d, want %d (%v)", depth, got, wantDNSX, x.inputs)
		}
	}
}

func TestBudgetIsRespected(t *testing.T) {
	x := &fakeExec{}
	rc, eng, root := newEnv(t, "example.com", Options{Budget: 3}, x)
	var lines string
	for _, h := range []string{"a", "b", "c", "d", "e"} {
		lines += jsLine("https://www.example.com/a.js", "internal-host", h+".example.com")
	}
	publish(t, rc, root, "js_secrets", "06/js.jsonl", "jsonl", lines, false)
	if err := eng.Process(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(x.cmds) != 3 {
		t.Fatalf("commands = %d, want exactly the budget (3): %v", len(x.cmds), x.cmds)
	}
	st := eng.Stats()
	if st.Commands != 3 || st.SkippedBudget == 0 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestUnresolvedNameIsNotProbed(t *testing.T) {
	x := &fakeExec{noResolve: map[string]bool{"ghost.example.com": true}}
	rc, eng, root := newEnv(t, "example.com", Options{}, x)
	publish(t, rc, root, "js_secrets", "06/js.jsonl", "jsonl", jsLine("https://www.example.com/a.js", "internal-host", "ghost.example.com"), false)
	if err := eng.Process(context.Background()); err != nil {
		t.Fatal(err)
	}
	if x.names("dnsx") != 1 || x.names("httpx") != 0 {
		t.Fatalf("cmds = %v", x.cmds)
	}
}

func TestDAGArtifactsDoNotTriggerFollowUps(t *testing.T) {
	x := &fakeExec{}
	rc, eng, root := newEnv(t, "example.com", Options{}, x)
	publish(t, rc, root, "subdomains", "01/s.txt", "text", "a.example.com\nb.example.com\n", true)
	publish(t, rc, root, "resolved_hosts", "01/r.txt", "text", "a.example.com\n", true)
	publish(t, rc, root, "alive_urls", "02/a.txt", "text", "http://a.example.com\n", true)
	if err := eng.Process(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(x.cmds) != 0 {
		t.Fatalf("the DAG handles its own stages: %v", x.cmds)
	}
}

func TestNewRequiresBus(t *testing.T) {
	root := t.TempDir()
	run := &storage.Run{RootDir: root, MetaDir: root}
	sc, _ := scanScope.FromTarget("example.com", scanScope.ModeDomain, nil, nil)
	rc := modules.NewRunContext("example.com", "recon", true, run, sc) // dry run: no bus
	_ = rc.EnableEventsWith(modules.EventsOptions{Extended: true})
	if _, err := New(rc, &fakeExec{}, Options{}); err == nil {
		t.Fatal("dry run must not start a discovery engine")
	}
}

func TestProcessStopsOnCancel(t *testing.T) {
	x := &fakeExec{}
	rc, eng, root := newEnv(t, "example.com", Options{}, x)
	publish(t, rc, root, "js_secrets", "06/js.jsonl", "jsonl", jsLine("https://www.example.com/a.js", "internal-host", "a.example.com"), false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := eng.Process(ctx); err == nil {
		t.Fatal("expected context error")
	}
	if len(x.cmds) != 0 {
		t.Fatal("cancelled context must not run commands")
	}
}
