// Package discovery implements the bounded recursive discovery loop.
//
// The artifact DAG still schedules the big stages. In recursive mode
// (--recursive), artifacts of those stages are additionally emitted as typed
// events (see internal/events) and a small set of subscribers react to NEW
// discoveries:
//
//   - a late in-scope DNS_NAME (found in JS, a crawl, a certificate, ...)
//     queues a dnsx -> httpx pass for that single name;
//   - a LIVE_URL found by such a follow-up probe queues a katana pass of
//     depth 1.
//
// Safety rules, all enforced by construction:
//
//   - Subscribers only enqueue jobs. Jobs run after the DAG, one at a time.
//   - Every command goes through the injected runner.Executor (the
//     scheduler-wrapped one), never os/exec.
//   - Every output is published through RunContext.AddArtifact, so the scope
//     filter stays the single choke point, and only the filtered file is
//     read back to emit follow-up events (with ParentID, so depth counts).
//   - The bus gates every event (scope first, then depth, dedup, budget).
//     Out-of-scope discoveries are dropped and logged to
//     scope-rejections.jsonl; they are never auto-allowed.
//   - A global command budget bounds follow-up work; loops end because the
//     bus delivers each event ID once and refuses events past MaxDepth.
package discovery

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/MikeRoss27/scanforge/internal/events"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

const (
	// DefaultDepth is the default maximum discovery depth (--recursive-depth).
	DefaultDepth = 2
	// DefaultBudget is the default follow-up command budget
	// (--recursive-budget).
	DefaultBudget = 200

	outDir = "07_recursive"

	// Source labels of events emitted by follow-up passes.
	sourceProbe = "recursive:httpx"
	sourceCrawl = "recursive:katana"
)

// Options configures an Engine. Zero values mean the defaults.
type Options struct {
	// MaxDepth bounds discovery chains (events deeper are dropped).
	MaxDepth int
	// Budget bounds the number of follow-up commands run.
	Budget int
	// Tool binaries; empty means the tool name.
	Dnsx, Httpx, Katana string
}

// Defaults fills zero values.
func (o Options) Defaults() Options {
	if o.MaxDepth <= 0 {
		o.MaxDepth = DefaultDepth
	}
	if o.Budget <= 0 {
		o.Budget = DefaultBudget
	}
	if o.Dnsx == "" {
		o.Dnsx = "dnsx"
	}
	if o.Httpx == "" {
		o.Httpx = "httpx"
	}
	if o.Katana == "" {
		o.Katana = "katana"
	}
	return o
}

// Stats summarizes a discovery run.
type Stats struct {
	Jobs, Commands, SkippedBudget, Failed int
}

type jobKind int

const (
	jobResolveProbe jobKind = iota
	jobCrawl
)

type job struct {
	kind jobKind
	ev   events.Event
}

// Engine is the discovery loop. Create it with New (which subscribes to the
// bus) and drive it with Process once the DAG has finished.
type Engine struct {
	rc   *modules.RunContext
	bus  *events.Bus
	exec runner.Executor
	opts Options

	mu    sync.Mutex
	queue []job
	stats Stats
	n     int
}

// New wires the engine to the run's event bus. It fails when events are not
// enabled (nil bus), which includes dry runs: nothing is ever invented.
func New(rc *modules.RunContext, exec runner.Executor, opts Options) (*Engine, error) {
	if rc == nil || exec == nil {
		return nil, errors.New("discovery: run context and executor are required")
	}
	bus := rc.EventBus()
	if bus == nil {
		return nil, errors.New("discovery: event bus is not enabled")
	}
	e := &Engine{rc: rc, bus: bus, exec: exec, opts: opts.Defaults()}
	bus.Subscribe(events.DNSName, e.onDNSName)
	bus.Subscribe(events.LiveURL, e.onLiveURL)
	// The scan target is already handled by the DAG: seed it so a crawl
	// rediscovering it does not trigger a redundant pass.
	if t := strings.TrimSpace(rc.Target); t != "" && !strings.ContainsAny(t, "/:") && net.ParseIP(t) == nil {
		if _, err := bus.Publish(events.Event{Type: events.DNSName, Value: t, Source: "target"}); err != nil {
			return nil, err
		}
	}
	return e, nil
}

// Stats returns a snapshot of the counters.
func (e *Engine) Stats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stats
}

// dagResolved are the artifacts whose names the DAG itself resolves and
// probes (subfinder/dnsx/httpx): a DNS_NAME from them needs no follow-up.
var dagResolved = map[string]struct{}{
	"subdomains":       {},
	"brute_subdomains": {},
	"resolved_hosts":   {},
	"alive_urls":       {},
	"target":           {},
}

func (e *Engine) onDNSName(ev events.Event) {
	if _, dag := dagResolved[ev.Source]; dag {
		return
	}
	e.enqueue(job{kind: jobResolveProbe, ev: ev})
}

func (e *Engine) onLiveURL(ev events.Event) {
	// LIVE_URLs of the DAG's own httpx are crawled by the DAG (katana
	// stage); only URLs found by a follow-up probe are new work.
	if ev.Source != sourceProbe {
		return
	}
	e.enqueue(job{kind: jobCrawl, ev: ev})
}

func (e *Engine) enqueue(j job) {
	e.mu.Lock()
	e.queue = append(e.queue, j)
	e.mu.Unlock()
}

func (e *Engine) pop() (job, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.queue) == 0 {
		return job{}, false
	}
	j := e.queue[0]
	e.queue = e.queue[1:]
	e.n++
	return j, true
}

// Process runs queued follow-up jobs, including those they cause, until the
// queue is empty, the budget is spent or ctx is cancelled. A failing job is
// reported as a warning and never aborts the run.
func (e *Engine) Process(ctx context.Context) error {
	if e.rc.DryRun {
		return nil
	}
	if err := os.MkdirAll(e.rc.Run.Path(outDir), 0o755); err != nil {
		return fmt.Errorf("discovery: create %s: %w", outDir, err)
	}
	for ctx.Err() == nil {
		j, ok := e.pop()
		if !ok {
			break
		}
		// Defense in depth: the bus already checked scope, re-check before
		// spending a command on the value.
		if !e.rc.IsInScope(j.ev.Value) {
			continue
		}
		var err error
		switch j.kind {
		case jobResolveProbe:
			err = e.resolveProbe(ctx, j)
		case jobCrawl:
			err = e.crawl(ctx, j)
		}
		e.mu.Lock()
		e.stats.Jobs++
		if err != nil {
			e.stats.Failed++
		}
		e.mu.Unlock()
		if errors.Is(err, errBudget) {
			e.rc.EmitWarning(fmt.Sprintf("recursive: command budget (%d) exhausted, remaining follow-ups skipped", e.opts.Budget))
			break
		}
		if err != nil && ctx.Err() == nil {
			e.rc.EmitWarning(fmt.Sprintf("recursive: %v", err))
		}
	}
	e.bus.Wait()
	return ctx.Err()
}

var errBudget = errors.New("recursive budget exhausted")

// spend reserves one command from the budget.
func (e *Engine) spend() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stats.Commands >= e.opts.Budget {
		e.stats.SkippedBudget++
		return errBudget
	}
	e.stats.Commands++
	return nil
}

var unsafeName = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func (e *Engine) prefix(j job) string {
	label := unsafeName.ReplaceAllString(j.ev.Value, "_")
	if len(label) > 60 {
		label = label[:60]
	}
	return fmt.Sprintf("%03d-%s", e.n, label)
}

// run logs and executes one command through the injected executor.
func (e *Engine) run(ctx context.Context, cmd runner.Command) error {
	if err := e.spend(); err != nil {
		return err
	}
	if err := runner.AppendCommandLog(e.rc.Run.CommandsLog, cmd); err != nil {
		return fmt.Errorf("write commands log: %w", err)
	}
	if _, err := e.exec.Run(ctx, cmd); err != nil {
		return fmt.Errorf("run %s: %w", cmd.Name, err)
	}
	return nil
}

// publish exposes a derived text file through AddArtifact (scope filter) and
// returns the surviving lines. The filter rewrites the file in place; only
// its filtered content is read back.
func (e *Engine) publish(name, rel string) ([]string, error) {
	if err := e.rc.AddArtifact(name, modules.Artifact{Name: name, Type: "text", Path: rel, Scoped: true}); err != nil {
		return nil, fmt.Errorf("publish %s: %w", name, err)
	}
	return readLines(e.rc.Run.Path(rel))
}

// resolveProbe runs dnsx then httpx for a single in-scope name.
func (e *Engine) resolveProbe(ctx context.Context, j job) error {
	p := e.prefix(j)
	inRel := filepath.Join(outDir, p+"-names.txt")
	dnsRaw := filepath.Join(outDir, p+"-dnsx.jsonl")
	dnsTxt := filepath.Join(outDir, p+"-resolved.txt")
	if err := os.WriteFile(e.rc.Run.Path(inRel), []byte(j.ev.Value+"\n"), 0o644); err != nil {
		return err
	}
	err := e.run(ctx, runner.Command{
		Name:       e.opts.Dnsx,
		Args:       []string{"-l", e.rc.Run.Path(inRel), "-silent", "-json", "-a", "-aaaa", "-resp"},
		Timeout:    2 * time.Minute,
		StdoutFile: e.rc.Run.Path(dnsRaw),
		StderrFile: e.rc.Run.Path(outDir, p+"-dnsx.stderr.log"),
	})
	if err != nil {
		return err
	}
	hosts, err := jsonStrings(e.rc.Run.Path(dnsRaw), "host")
	if err != nil {
		return err
	}
	if err := writeLines(e.rc.Run.Path(dnsTxt), hosts); err != nil {
		return err
	}
	resolved, err := e.publish("recursive.resolved_hosts", dnsTxt)
	if err != nil || len(resolved) == 0 {
		return err
	}

	httpRaw := filepath.Join(outDir, p+"-httpx.jsonl")
	aliveTxt := filepath.Join(outDir, p+"-alive.txt")
	args := []string{"-l", e.rc.Run.Path(dnsTxt), "-silent", "-json", "-status-code", "-title", "-tech-detect"}
	args = append(args, e.rc.ProxyArgs("-proxy")...)
	args = append(args, e.rc.HeaderArgs("-H")...)
	err = e.run(ctx, runner.Command{
		Name:       e.opts.Httpx,
		Args:       args,
		Timeout:    3 * time.Minute,
		StdoutFile: e.rc.Run.Path(httpRaw),
		StderrFile: e.rc.Run.Path(outDir, p+"-httpx.stderr.log"),
	})
	if err != nil {
		return err
	}
	urls, err := jsonStrings(e.rc.Run.Path(httpRaw), "url")
	if err != nil {
		return err
	}
	if err := writeLines(e.rc.Run.Path(aliveTxt), urls); err != nil {
		return err
	}
	alive, err := e.publish("recursive.alive_urls", aliveTxt)
	if err != nil {
		return err
	}
	return e.emit(j.ev, sourceProbe, events.LiveURL, alive)
}

// crawl runs katana with depth 1 on a single in-scope URL.
func (e *Engine) crawl(ctx context.Context, j job) error {
	p := e.prefix(j)
	out := filepath.Join(outDir, p+"-katana.txt")
	args := []string{"-u", j.ev.Value, "-silent", "-depth", "1"}
	if waf := e.rc.GetWAFInfo(); waf.Detected {
		args = append(args, "-rate-limit", "5", "-c", "2")
	}
	args = append(args, e.rc.ProxyArgs("-proxy")...)
	args = append(args, e.rc.HeaderArgs("-H")...)
	err := e.run(ctx, runner.Command{
		Name:       e.opts.Katana,
		Args:       args,
		Timeout:    5 * time.Minute,
		StdoutFile: e.rc.Run.Path(out),
		StderrFile: e.rc.Run.Path(outDir, p+"-katana.stderr.log"),
	})
	if err != nil {
		return err
	}
	// katana may write nothing at all; the artifact filter needs a file.
	if _, statErr := os.Stat(e.rc.Run.Path(out)); statErr != nil {
		if err := writeLines(e.rc.Run.Path(out), nil); err != nil {
			return err
		}
	}
	crawled, err := e.publish("recursive.crawled_urls", out)
	if err != nil {
		return err
	}
	var found []events.Extracted
	for _, u := range crawled {
		found = append(found, events.URLDiscoveries(u)...)
	}
	return e.emitExtracted(j.ev, sourceCrawl, found)
}

func (e *Engine) emit(parent events.Event, source string, t events.Type, values []string) error {
	found := make([]events.Extracted, 0, len(values))
	for _, v := range values {
		found = append(found, events.Extracted{Type: t, Value: v})
	}
	return e.emitExtracted(parent, source, found)
}

func (e *Engine) emitExtracted(parent events.Event, source string, found []events.Extracted) error {
	for _, x := range found {
		ev := events.Derive(parent, x.Type, x.Value, source)
		ev.ScopeRef = x.ScopeRef
		if _, err := e.bus.Publish(ev); err != nil {
			return err
		}
	}
	return nil
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}

func writeLines(path string, lines []string) error {
	data := ""
	if len(lines) > 0 {
		data = strings.Join(lines, "\n") + "\n"
	}
	return os.WriteFile(path, []byte(data), 0o644)
}

// jsonStrings returns the deduplicated non-empty string field of each JSONL
// record. A missing file is an empty result (the tool wrote nothing).
func jsonStrings(path, field string) ([]string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	seen := map[string]struct{}{}
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var rec map[string]any
		if json.Unmarshal(sc.Bytes(), &rec) != nil {
			continue
		}
		v, _ := rec[field].(string)
		if _, err := url.Parse(v); v == "" || err != nil {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out, sc.Err()
}
