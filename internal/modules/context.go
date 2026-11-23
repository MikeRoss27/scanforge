// Package modules defines the scanner integration contract (Module, artifacts,
// run context) and the registry used to resolve them.
package modules

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/MikeRoss27/scanforge/internal/events"
	scanScope "github.com/MikeRoss27/scanforge/internal/scope"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

type Artifact struct {
	Name string
	Type string
	Path string
	// Scoped marks line-oriented text artifacts that must be filtered
	// against the effective scope before publication: host, URL, IP and
	// host:port lists consumed by downstream modules. Raw tool outputs
	// (JSONL/XML) and derived data (wordlists, paths, secrets) must NOT set
	// it: they are produced from already-scoped inputs and their lines do
	// not parse as targets. The legacy scopedTextArtifacts allowlist is kept
	// as a safety net for the well-known artifact names.
	Scoped bool
}

type RunContext struct {
	Target         string
	Profile        string
	DryRun         bool
	Run            *storage.Run
	Scope          *scanScope.Scope
	Artifacts      map[string]Artifact
	artifactErrors map[string]error
	artifactStates map[string]*artifactState
	mu             sync.RWMutex

	// Proxy is an optional HTTP/SOCKS proxy (e.g. a Caido or Burp listener
	// such as http://127.0.0.1:8080) that HTTP-capable modules route their
	// traffic through, so findings can be intercepted and triaged manually.
	Proxy string
	// Headers are raw "Name: Value" entries applied to every outgoing HTTP
	// request by modules that support it (e.g. session cookies or auth
	// tokens for authenticated scanning).
	Headers []string
	// Nuclei carries nuclei-specific tuning that has no equivalent in other
	// modules (severity/tag filtering, rate limiting, custom templates).
	Nuclei NucleiOptions
	// Ffuf carries ffuf-specific tuning (wordlist selection, status-code
	// filtering).
	Ffuf FfufOptions
	// NmapConcurrency bounds how many nmap processes run at once. <= 0 means
	// the module picks its own default.
	NmapConcurrency int
	// WordPress carries WordPress-engagement tuning (enumeration mode,
	// aggressive wordlists, opt-in brute force).
	WordPress WordPressOptions

	// events is the optional discovery event bus (nil unless --events).
	events *events.Bus

	onFinding func(Finding)
	onWarn    func(string)
	// onProgress optionally receives live module progress for the volatile
	// console line. Modules that expose no reliable metrics stay silent.
	onProgress func(ModuleProgressEvent)
	// rejected counts per-artifact how many lines the scope filter dropped,
	// so consumers can tell an empty input apart from a filtered one.
	rejected map[string]int
	// waf is wafw00f's detection result, read by request-heavy modules
	// (ffuf, nuclei, katana) to decide whether to throttle and vary their
	// request fingerprint. Zero value means no WAF was detected, or
	// wafw00f was not part of the profile.
	waf WAFInfo
}

// WAFInfo describes whether wafw00f detected a WAF in front of the target
// and which product(s), so request-heavy modules can back off and vary
// their footprint instead of hammering a filtering edge with a fixed
// signature.
type WAFInfo struct {
	Detected bool
	Names    []string
}

// SetWAFInfo records wafw00f's detection result. Safe for concurrent use;
// called at most once per run, by wafw00f itself after it finishes.
func (c *RunContext) SetWAFInfo(info WAFInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.waf = info
}

// GetWAFInfo returns wafw00f's detection result, or the zero value when
// wafw00f was not selected for this run or found nothing.
func (c *RunContext) GetWAFInfo() WAFInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.waf
}

// artifactState lets a running module wait for an optional artifact without
// imposing a scheduler dependency. done closes when the artifact is published
// or when its selected producer finishes without publishing it.
type artifactState struct {
	expected bool
	done     bool
	ready    chan struct{}
}

// Finding is a single vulnerability/exposure a module has just discovered.
// Modules report these as soon as they are found (mid-scan, not only once the
// module finishes) so an operator watching the run sees results live.
type Finding struct {
	// Module is the reporting module's name (e.g. "nuclei", "jssecrets").
	Module string
	// Severity is one of critical/high/medium/low/info; empty is allowed for
	// informational modules that don't rate findings.
	Severity string
	// Title is a short human-readable label, e.g. a nuclei template name or
	// secret pattern id.
	Title string
	// Target is the host/URL the finding was observed on.
	Target string
	// Detail is optional extra context (matched path, snippet, CVE id).
	Detail string
}

// SetFindingSink installs the callback used to report findings live, e.g. to
// forward them onto the orchestrator's event channel. Must be called before
// modules start running; the sink itself must be safe for concurrent use
// since modules run concurrently within a wave.
func (c *RunContext) SetFindingSink(sink func(Finding)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onFinding = sink
}

// EmitFinding reports a finding the instant a module discovers it. Safe to
// call from concurrent goroutines; a no-op when no sink is installed (e.g.
// unit tests that construct a RunContext directly without an orchestrator).
func (c *RunContext) EmitFinding(f Finding) {
	c.mu.RLock()
	sink := c.onFinding
	c.mu.RUnlock()
	if sink != nil {
		sink(f)
	}
}

// SetWarningSink installs the callback used to surface module-level warnings
// (empty inputs, degraded steps). Same concurrency contract as SetFindingSink.
func (c *RunContext) SetWarningSink(sink func(string)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onWarn = sink
}

// EmitWarning surfaces a module-level warning in the live event stream. Safe
// to call from concurrent goroutines; a no-op when no sink is installed.
func (c *RunContext) EmitWarning(message string) {
	c.mu.RLock()
	sink := c.onWarn
	c.mu.RUnlock()
	if sink != nil {
		sink(message)
	}
}

// SetProgressSink installs the callback used to publish live progress (real
// counts only) while a module runs. Same concurrency contract as
// SetFindingSink.
func (c *RunContext) SetProgressSink(sink func(ModuleProgressEvent)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onProgress = sink
}

// EmitProgress publishes a live progress update for the volatile console
// line. Safe to call from concurrent goroutines; a no-op when no sink is
// installed. Modules must only emit values they actually measured.
func (c *RunContext) EmitProgress(e ModuleProgressEvent) {
	c.mu.RLock()
	sink := c.onProgress
	c.mu.RUnlock()
	if sink != nil {
		sink(e)
	}
}

// ModuleProgressEvent is one live progress update published by a module.
type ModuleProgressEvent struct {
	Name    string
	Current int
	Total   int
	Unit    string
	Message string
}

// RejectedCount returns how many lines of the named artifact were dropped by
// scope filtering. Zero means either nothing was rejected or the artifact was
// never scope-filtered (missing scope, dry run, non-text artifact).
func (c *RunContext) RejectedCount(name string) int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rejected[name]
}

// FfufOptions configures the ffuf module's fuzzing inputs.
type FfufOptions struct {
	// Wordlist is the directory/file wordlist used for path fuzzing. Empty
	// means the module default (/usr/share/wordlists/dirb/common.txt).
	Wordlist string
	// FilterCodes are comma-separated HTTP status codes to filter out
	// (ffuf -fc), e.g. "404,500".
	FilterCodes string
}

// WordPressOptions configures how aggressively the WordPress modules
// interrogate their targets. The defaults are strictly passive: nothing
// sends fuzzing traffic and the brute-force module stays inert unless
// explicitly enabled with --wp-bruteforce.
type WordPressOptions struct {
	// DetectionMode is "passive" (default), "mixed" or "aggressive" and
	// controls wpplugins/wpthemes probing.
	DetectionMode string
	// Wordlist overrides the bundled plugin/theme slug list used in
	// aggressive mode (one slug per line).
	Wordlist string
	// Bruteforce enables the wpbrute module. Off by default everywhere,
	// including the wp preset: it only runs when the operator passes
	// --wp-bruteforce and confirms the scope.
	Bruteforce bool
	// PasswordsFile is the explicit password wordlist wpbrute reads. Always
	// required when Bruteforce is true (no defaults bundled).
	PasswordsFile string
	// BruteMax caps password attempts per user (default 100).
	BruteMax int
	// BruteMethod picks the auth probe used for brute force: "login"
	// (wp-login.php form, default) or "xmlrpc" (wp.getUsersBlogs).
	BruteMethod string
}

// NucleiOptions configures the nuclei module's template selection and pacing.
type NucleiOptions struct {
	Severity        string
	ExcludeSeverity string
	Tags            string
	ExcludeTags     string
	RateLimit       int
	TemplatesDir    string
	UpdateTemplates bool
	// Timeout bounds the whole nuclei invocation. Zero means the module's
	// default (30 minutes). Long scans - big target lists, slow proxies -
	// frequently need more headroom.
	Timeout time.Duration
	// Headless enables headless-mode templates (renders pages in a browser).
	Headless bool
	// IncludeCustomTemplates appends the repository's bundled custom template
	// directory to the nuclei scan.
	IncludeCustomTemplates bool
	// CustomTemplatesDir overrides the bundled custom template directory path.
	CustomTemplatesDir string
	// FullScan disables nuclei's technology-aware automatic scan (-as) and
	// runs every loaded template against every host regardless of detected
	// tech. Default is -as on: a single generic host already loads ~7000
	// templates / ~17000 planned requests, so blindly firing the whole
	// catalog at more than one or two hosts reliably exceeds the default
	// 30-minute Timeout before anything useful is produced. FullScan trades
	// that speed for exhaustive coverage; raise Timeout accordingly.
	FullScan bool
}

func NewRunContext(target, profile string, dryRun bool, run *storage.Run, scopes ...*scanScope.Scope) *RunContext {
	var allowedScope *scanScope.Scope
	if len(scopes) > 0 {
		allowedScope = scopes[0]
	}
	return &RunContext{
		Target:         target,
		Profile:        profile,
		DryRun:         dryRun,
		Run:            run,
		Scope:          allowedScope,
		Artifacts:      make(map[string]Artifact),
		artifactErrors: make(map[string]error),
		artifactStates: make(map[string]*artifactState),
		rejected:       make(map[string]int),
	}
}

// ExpectArtifact declares that a selected module may publish name. The
// orchestrator calls this before dispatching any module.
func (c *RunContext) ExpectArtifact(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	state := c.artifactState(name)
	state.expected = true
	if _, ok := c.Artifacts[name]; ok {
		c.finishArtifactState(state)
	}
}

// CompleteArtifact marks a producer finished. Waiters wake even when the
// producer failed and no artifact was published.
func (c *RunContext) CompleteArtifact(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.finishArtifactState(c.artifactState(name))
}

// WaitArtifact waits for an optional selected producer. It returns found=false
// immediately when no selected module produces name, and after producer
// completion when the producer failed to publish it.
func (c *RunContext) WaitArtifact(ctx context.Context, name string) (artifact Artifact, found bool, err error) {
	c.mu.Lock()
	if artifact, found = c.Artifacts[name]; found {
		c.mu.Unlock()
		return artifact, true, nil
	}
	state, tracked := c.artifactStates[name]
	if !tracked || !state.expected {
		c.mu.Unlock()
		return Artifact{}, false, nil
	}
	ready := state.ready
	c.mu.Unlock()

	select {
	case <-ctx.Done():
		return Artifact{}, false, ctx.Err()
	case <-ready:
	}
	artifact, found = c.GetArtifact(name)
	return artifact, found, nil
}

func (c *RunContext) artifactState(name string) *artifactState {
	state, ok := c.artifactStates[name]
	if !ok {
		state = &artifactState{ready: make(chan struct{})}
		c.artifactStates[name] = state
	}
	return state
}

func (c *RunContext) finishArtifactState(state *artifactState) {
	if state.done {
		return
	}
	state.done = true
	close(state.ready)
}

// AddArtifact publishes a module output for downstream consumers. Text artifacts
// are filtered in place first, making this the central scope boundary for all
// line-oriented host, URL, IP, and host:port lists.
func (c *RunContext) AddArtifact(name string, artifact Artifact) error {
	if err := c.addArtifact(name, artifact); err != nil {
		return err
	}
	c.emitArtifactEvents(name, artifact)
	return nil
}

func (c *RunContext) addArtifact(name string, artifact Artifact) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.filterArtifact(name, artifact); err != nil {
		c.artifactErrors[name] = err
		return err
	}
	c.Artifacts[name] = artifact
	delete(c.artifactErrors, name)
	c.finishArtifactState(c.artifactState(name))
	return nil
}

// lockedScope lets the event bus consult the scope under the RunContext lock,
// since AllowDiscoveredHost mutates the scope concurrently.
type lockedScope struct{ c *RunContext }

func (l lockedScope) IsAllowed(target string) bool {
	l.c.mu.RLock()
	defer l.c.mu.RUnlock()
	return l.c.Scope.IsAllowed(target)
}

// EnableEvents turns on the experimental discovery event bus (off by
// default): artifacts listed in events.ArtifactEventTypes are additionally
// emitted as events, persisted to 00_meta/events.jsonl and gated by the
// effective scope. It requires a scope and a real (non-dry) run, and is a
// no-op otherwise.
func (c *RunContext) EnableEvents() error {
	if c.Scope == nil || c.Run == nil || c.DryRun {
		return nil
	}
	bus, err := events.New(events.Options{MetaDir: c.Run.MetaDir, Scope: lockedScope{c}})
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.events = bus
	c.mu.Unlock()
	return nil
}

// EventBus returns the discovery event bus, or nil when events are disabled.
func (c *RunContext) EventBus() *events.Bus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.events
}

func (c *RunContext) emitArtifactEvents(name string, artifact Artifact) {
	bus := c.EventBus()
	typ, ok := events.ArtifactEventTypes[name]
	if bus == nil || !ok || artifact.Type != "text" {
		return
	}
	if _, err := events.EmitLines(bus, c.Run.Path(artifact.Path), typ, name); err != nil {
		c.EmitWarning(fmt.Sprintf("events: %v", err))
	}
	bus.Wait()
}

func (c *RunContext) GetArtifact(name string) (Artifact, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	art, ok := c.Artifacts[name]
	return art, ok
}

// IsInScope reports whether value is within the configured scope. A missing
// scope (tests, some dry runs) allows everything.
func (c *RunContext) IsInScope(value string) bool {
	if c.Scope == nil {
		return true
	}
	return c.Scope.IsAllowed(value)
}

// scopeAddition is one audit line of 00_meta/scope-additions.jsonl: a host a
// module added to the effective scope mid-run, with why.
type scopeAddition struct {
	Timestamp string `json:"timestamp"`
	Host      string `json:"host"`
	Source    string `json:"source"`
	Reason    string `json:"reason"`
}

// AllowDiscoveredHost adds an exact host discovered mid-run — a backend
// endpoint found in the target's own client code — to the effective scope so
// downstream modules may probe the target's own infrastructure. It records
// provenance to 00_meta/scope-additions.jsonl for audit. It is a no-op on a
// nil scope or a dry run, and returns true only when the host was newly
// allowed. The scope mutation happens under the same lock that guards
// filterArtifact, so it is race-free with artifact publication.
func (c *RunContext) AllowDiscoveredHost(host, source, reason string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Scope == nil || c.Run == nil || c.DryRun {
		return false
	}
	if !c.Scope.AllowHost(host) {
		return false
	}
	rec := scopeAddition{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Host:      host,
		Source:    source,
		Reason:    reason,
	}
	if data, err := json.Marshal(rec); err == nil {
		path := c.Run.Path("00_meta", "scope-additions.jsonl")
		if f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			_, _ = f.Write(append(data, '\n'))
			_ = f.Close()
		}
	}
	return true
}

func (c *RunContext) MustArtifact(name string) (Artifact, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if art, ok := c.Artifacts[name]; ok {
		return art, nil
	}
	if err, ok := c.artifactErrors[name]; ok {
		return Artifact{}, fmt.Errorf("artifact %q failed scope validation: %w", name, err)
	}
	available := []string{}
	for k := range c.Artifacts {
		available = append(available, k)
	}
	return Artifact{}, fmt.Errorf("required artifact %q not found (available: %s)", name, strings.Join(available, ", "))
}

type scopeRejection struct {
	Timestamp string `json:"timestamp"`
	Artifact  string `json:"artifact"`
	Path      string `json:"path"`
	Value     string `json:"value"`
	Reason    string `json:"reason"`
}

var scopedTextArtifacts = map[string]struct{}{
	"subdomains":          {},
	"brute_subdomains":    {},
	"resolved_hosts":      {},
	"alive_urls":          {},
	"crawled_urls":        {},
	"open_ports":          {},
	"historical_urls":     {},
	"attack_surface_urls": {},
}

func (c *RunContext) filterArtifact(name string, artifact Artifact) error {
	_, legacyScoped := scopedTextArtifacts[name]
	if c.Scope == nil || c.Run == nil || c.DryRun || artifact.Type != "text" || (!artifact.Scoped && !legacyScoped) {
		return nil
	}

	path := c.Run.Path(artifact.Path)
	input, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open artifact %q: %w", path, err)
	}
	defer func() { _ = input.Close() }()

	tmp, err := os.CreateTemp(filepath.Dir(path), ".scope-filter-*")
	if err != nil {
		return fmt.Errorf("create filtered artifact: %w", err)
	}
	tmpPath := tmp.Name()
	keepTemp := false
	defer func() {
		_ = tmp.Close()
		if !keepTemp {
			_ = os.Remove(tmpPath)
		}
	}()

	scanner := bufio.NewScanner(input)
	// Crawled and historical URLs routinely exceed bufio's 64KB default
	// token limit; the consumers of these artifacts (e.g. attacksurface)
	// already read them with a 1MB ceiling, and a hard failure here would
	// mark the producing module failed even though its output is valid.
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	writer := bufio.NewWriter(tmp)
	var rejected []scopeRejection
	for scanner.Scan() {
		value := strings.TrimSpace(scanner.Text())
		if value == "" {
			continue
		}
		if !c.Scope.IsAllowed(value) {
			c.rejected[name]++
			rejected = append(rejected, scopeRejection{
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
				Artifact:  name,
				Path:      artifact.Path,
				Value:     value,
				Reason:    "outside configured scope",
			})
			continue
		}
		if _, err := writer.WriteString(value + "\n"); err != nil {
			return fmt.Errorf("write filtered artifact: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read artifact %q: %w", path, err)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush filtered artifact: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close filtered artifact: %w", err)
	}
	if err := os.Chmod(tmpPath, 0644); err != nil {
		return fmt.Errorf("set filtered artifact permissions: %w", err)
	}
	// Record rejections before replacing the artifact: if the log write
	// fails, the artifact is left unpublished and the original file intact,
	// keeping the state consistent for downstream consumers.
	if len(rejected) > 0 {
		if err := c.appendScopeRejections(rejected); err != nil {
			return err
		}
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace artifact with filtered output: %w", err)
	}
	keepTemp = true

	return nil
}

func (c *RunContext) appendScopeRejections(rejections []scopeRejection) error {
	path := filepath.Join(c.Run.MetaDir, "scope-rejections.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open scope rejection log: %w", err)
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	for _, rejection := range rejections {
		if err := encoder.Encode(rejection); err != nil {
			return fmt.Errorf("write scope rejection log: %w", err)
		}
	}
	if c.Run.Manifest.Outputs == nil {
		c.Run.Manifest.Outputs = make(map[string]string)
	}
	c.Run.Manifest.Outputs["scope_rejections"] = "00_meta/scope-rejections.jsonl"
	return nil
}
