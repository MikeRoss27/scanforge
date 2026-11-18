package console

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/MikeRoss27/scanforge/internal/ascii"
	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	"github.com/charmbracelet/x/ansi"
)

// Options configures a Renderer.
type Options struct {
	// Out is the destination of the rendered output (os.Stdout in production).
	Out io.Writer
	// Terminal describes the output destination; use DetectTerminal(Out).
	Terminal Terminal
	// Colors switches ANSI styling on/off; colors must never reach piped or
	// machine-readable output. Use DetectTerminal + colorEnabled.
	Colors bool
	// Verbosity selects the output level (see Verbosity).
	Verbosity Verbosity
	// Clock is injectable so tests are deterministic. Defaults to time.Now.
	Clock func() time.Time
	// Profile is used in actionable error hints (`scanforge doctor ...`).
	Profile string
	// DryRun disables the volatile progress line: a dry run finishes in
	// milliseconds and its command list is the point.
	DryRun bool
	// Spinner selects the volatile-line animation. The zero value is the
	// default forge animation; use ResolveSpinner to honor SCANFORGE_SPINNER.
	Spinner SpinnerStyle
}

// Renderer turns orchestrator events into a chronological, tagged terminal
// log. It owns all terminal writes for the scan: events, phases, the
// volatile progress line, the header and the summary never interleave.
type Renderer struct {
	out           io.Writer
	th            theme
	term          Terminal
	verbosity     Verbosity
	clock         func() time.Time
	profile       string
	dryRun        bool
	showLifecycle bool

	mu           sync.Mutex
	lastPhase    string
	pendingPhase string // phase waiting for its first visible line
	pendingWave  int
	progress     *progressTracker
	findings     *findingIndex
	ticker       *time.Ticker
	tickerStop   chan struct{}
	volatileRows int
	volatile     bool // a progress line is currently on screen
}

// New builds a renderer. A nil Out is replaced by a discard writer so tests
// can construct renderers cheaply.
func New(opts Options) *Renderer {
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	out := opts.Out
	if out == nil {
		out = io.Discard
	}
	return &Renderer{
		out:           out,
		th:            newTheme(opts.Colors),
		term:          opts.Terminal,
		verbosity:     opts.Verbosity,
		clock:         clock,
		profile:       opts.Profile,
		dryRun:        opts.DryRun,
		showLifecycle: opts.Verbosity >= Normal && (!opts.DryRun || opts.Verbosity >= Verbose),
		progress:      newProgressTracker(opts.Spinner),
		findings:      newFindingIndex(),
	}
}

// Consume renders events until the channel is closed, then finalizes the
// volatile line. It is the streaming replacement for a fullscreen TUI: the
// caller's goroutine blocks here while the orchestrator runs in the
// background.
func (r *Renderer) Consume(events <-chan orchestrator.Event) {
	for ev := range events {
		r.Handle(ev)
	}
	r.finish()
}

// Handle renders one event. Events arrive serialized through the
// orchestrator's channel, so sequential handling is race-free.
func (r *Renderer) Handle(ev orchestrator.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	switch e := ev.(type) {
	case orchestrator.WaveStartEvent:
		r.handleWave(e)
	case orchestrator.ModuleStartEvent:
		r.progress.start(e.Name, r.clock())
		r.printEventLocked(r.renderEvent(ev))
	case orchestrator.ModuleDoneEvent:
		r.progress.finish(e.Name)
		r.printEventLocked(r.renderEvent(ev))
		r.syncTickerLocked()
	case orchestrator.ModuleProgressEvent:
		// Real progress from a module: refresh the volatile line only.
		r.progress.update(e, r.clock())
		r.redrawVolatileLocked()
	case orchestrator.FindingEvent:
		// Deduplicate evidence: HIGH/CRITICAL types expand once and count
		// their repeats, compact findings print each distinct value once.
		show, expanded := r.findings.record(e, r.verbosity)
		if !show {
			return
		}
		if expanded {
			severity := strings.ToUpper(strings.TrimSpace(e.Severity))
			if severity == "" {
				severity = "INFO"
			}
			title := singleLine(e.Title)
			if title == "" {
				title = singleLine(e.Module)
			}
			r.printEventLocked(r.expandedFinding(severity, title, e))
			return
		}
		r.printEventLocked(r.compactFinding(e))
	default:
		r.printEventLocked(r.renderEvent(ev))
	}
}

// handleWave records the phase header when the wave moved to a new phase.
// The header is printed lazily, right before the first visible line of the
// wave: a wave that produces no output (analysis-only modules in a dry run,
// for instance) must not leave a dangling separator. The wave's module list
// is the source of truth — no invented phases.
func (r *Renderer) handleWave(e orchestrator.WaveStartEvent) {
	if r.verbosity < Normal {
		return
	}
	phase := phaseFor(e.Modules)
	switch phase {
	case "":
		return
	case r.lastPhase:
		// The current phase is already on screen; an older pending header
		// belonged to a wave that never printed anything.
		r.pendingPhase, r.pendingWave = "", 0
		return
	case r.pendingPhase:
		return
	}
	r.pendingPhase, r.pendingWave = phase, e.Wave
}

// flushPhaseLocked prints the pending phase separator. Callers hold r.mu and
// have already finalized any volatile progress line.
func (r *Renderer) flushPhaseLocked() {
	if r.pendingPhase == "" {
		return
	}
	phase, wave := r.pendingPhase, r.pendingWave
	r.pendingPhase, r.pendingWave = "", 0
	if phase == r.lastPhase {
		return
	}
	r.lastPhase = phase
	r.writeLineLocked(r.phaseHeader(phase, wave))
}

// finish finalizes the volatile line at the end of the event stream.
func (r *Renderer) finish() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clearVolatileLocked()
	r.stopTickerLocked()
	r.pendingPhase, r.pendingWave = "", 0
}

// ---------------------------------------------------------------------------
// Direct messages (outside the event stream)
// ---------------------------------------------------------------------------

// Info prints an [INF] line for app-level events that are not orchestrator
// events (report generation, webhook failures).
func (r *Renderer) Info(format string, args ...any) {
	r.emit(TagInfo, fmt.Sprintf(format, args...))
}

// Warn prints a [WRN] line.
func (r *Renderer) Warn(format string, args ...any) {
	r.emit(TagWarn, fmt.Sprintf(format, args...))
}

// Debug prints a dim, untagged diagnostic line for -vv/-vvv: the shell
// command an external tool ran and where its output went. No timestamp or
// tag — these lines are a transcript, not events.
func (r *Renderer) Debug(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	message := singleLine(fmt.Sprintf(format, args...))
	r.clearVolatileLocked()
	r.flushPhaseLocked()
	r.writeRowsLocked([]string{r.th.Dim(message)})
	r.redrawVolatileLocked()
}

// Error prints an [ERR] line.
func (r *Renderer) Error(format string, args ...any) {
	r.emit(TagError, fmt.Sprintf(format, args...))
}

// Command prints one shell command of a dry run. Commands stay unframed and
// unwrapped so they remain copy/pasteable; they are a transcript, not events.
// Printing through the renderer keeps phase headers and the volatile line in
// sync with the rest of the scan.
func (r *Renderer) Command(command string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clearVolatileLocked()
	r.flushPhaseLocked()
	_, _ = fmt.Fprintln(r.out, r.th.Accent("$")+" "+r.th.Dim(singleLine(command)))
	r.redrawVolatileLocked()
}

// Blank writes an empty line without touching the volatile progress line.
func (r *Renderer) Blank() {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, _ = fmt.Fprintln(r.out)
}

// PrintBanner renders the ScanForge wordmark with a dim tagline. The text
// is plain (owned by the ascii package); the renderer applies the brand
// color so the banner follows the same color rules as the rest of the run.
func (r *Renderer) PrintBanner(wordmark, tagline string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	monoSmith := strings.Split(ascii.BannerSmith(false, false), "\n")
	colorSmith := strings.Split(ascii.BannerSmith(true, r.th.truecolor), "\n")
	for i, line := range strings.Split(wordmark, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		styled := r.th.Accent(line)
		if r.th.enabled && i < len(monoSmith) && strings.HasPrefix(line, monoSmith[i]) {
			styled = colorSmith[i] + r.th.Accent(strings.TrimPrefix(line, monoSmith[i]))
		}
		for _, row := range wrapLine(styled, r.term.Width, 0) {
			_, _ = fmt.Fprintln(r.out, row)
		}
	}
	if tagline != "" {
		_, _ = fmt.Fprintln(r.out, r.th.Dim(tagline))
	}
	_, _ = fmt.Fprintln(r.out)
}

func (r *Renderer) emit(tag, message string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.printEventLocked([]string{r.eventLine(tag, singleLine(message))})
}

// RunHeader is the compact run configuration block that replaces the old
// boxed intro:
//
//	Target      example.com
//	Profile     web
//	Scope       domain + subdomains
//	Modules     14
//	Output      runs/example.com/2026-11-18_04-32-11
type RunHeader struct {
	Target    string
	Profile   string
	Scope     string
	Modules   int
	Proxy     string
	Headers   []string
	DryRun    bool
	OutputDir string
}

// PrintHeader renders the run configuration block. Quiet mode skips it:
// the operator asked for findings and errors, not setup echo.
func (r *Renderer) PrintHeader(h RunHeader) {
	if r.verbosity <= Quiet {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	profile := h.Profile
	if h.DryRun {
		profile += " · dry run"
	}
	items := []struct{ label, value string }{
		{"Target", h.Target},
		{"Profile", profile},
		{"Scope", h.Scope},
		{"Modules", itoa(h.Modules)},
	}
	if h.Proxy != "" {
		items = append(items, struct{ label, value string }{"Proxy", h.Proxy})
	}
	if len(h.Headers) > 0 {
		items = append(items, struct{ label, value string }{"Headers", fmt.Sprintf("%d custom", len(h.Headers))})
	}
	items = append(items, struct{ label, value string }{"Output", h.OutputDir})

	var rows []string
	for _, row := range items {
		if row.value == "" {
			continue
		}
		rows = append(rows, r.fieldRows(row.label, row.value)...)
	}
	r.writeRowsLocked(rows)
}

// fieldRows renders a key/value row, wrapping the value across several
// lines (aligned under the value column) when it exceeds the width.
func (r *Renderer) fieldRows(label, value string) []string {
	pad := labelWidth - len([]rune(label))
	if pad < 1 {
		pad = 1
	}
	prefix := r.th.Subtle(label) + strings.Repeat(" ", pad)
	return valueRows(prefix, value, r.term.Width)
}

// ---------------------------------------------------------------------------
// Write plumbing
// ---------------------------------------------------------------------------

// writeLineLocked writes one line, wrapping it into the terminal width.
// Event log lines are never wrapped — they are truncated with an ellipsis
// instead, so one event stays one grep-able line; blocks and sections
// wrap normally. The check looks through ANSI styling, which colored
// event lines lead with.
func (r *Renderer) writeLineLocked(line string) {
	width := r.term.Width
	if width <= 0 {
		width = DefaultWidth
	}
	if strings.HasPrefix(ansi.Strip(line), "[") {
		_, _ = fmt.Fprintln(r.out, ansi.Truncate(line, width, "…"))
		return
	}
	for _, row := range wrapLine(line, width, eventIndent(line)) {
		_, _ = fmt.Fprintln(r.out, row)
	}
}

// writeRowsLocked writes pre-built rows, wrapping any line that exceeds
// the terminal width. Callers hold r.mu.
func (r *Renderer) writeRowsLocked(rows []string) {
	for _, line := range rows {
		r.writeLineLocked(line)
	}
}

// printEventLocked renders a batch of event lines: finalize the volatile
// line, print, redraw the volatile line for the modules still running.
func (r *Renderer) printEventLocked(lines []string) {
	if len(lines) == 0 {
		return
	}
	r.clearVolatileLocked()
	r.flushPhaseLocked()
	r.writeRowsLocked(lines)
	r.redrawVolatileLocked()
}

// redrawVolatileLocked redraws the volatile progress line when modules are
// still running. Everything that could disturb it (an event, a phase
// change) clears and redraws it around itself.
func (r *Renderer) redrawVolatileLocked() {
	if !r.volatileAllowed() || !r.progress.running() {
		return
	}
	now := r.clock()
	line := r.progress.view(now, r.term.Width, r.th)
	if line == "" {
		return
	}
	var update strings.Builder
	update.WriteString(r.eraseVolatileLocked())
	if r.progress.spinner == SpinnerForge && r.term.Width >= 50 {
		rows := forgeLoadingRows(now, r.th)
		for i, row := range rows {
			if i == len(rows)/2 {
				row += "  " + ansi.Truncate(line, r.term.Width-forgeWidth-3, "…")
			}
			update.WriteString("\r\x1b[2K" + row)
			if i < len(rows)-1 {
				update.WriteByte('\n')
				r.volatileRows++
			}
		}
	} else {
		update.WriteString("\r\x1b[2K" + line)
	}
	// Send one terminal write per frame instead of clearing and drawing each
	// row separately; the user never sees a half-erased animation block.
	_, _ = fmt.Fprint(r.out, update.String())
	r.volatile = true
	r.ensureTickerLocked()
}

func (r *Renderer) eraseVolatileLocked() string {
	if !r.volatile {
		return ""
	}
	clear := "\r\x1b[2K" + strings.Repeat("\x1b[1A\r\x1b[2K", r.volatileRows)
	r.volatileRows = 0
	r.volatile = false
	return clear
}

// clearVolatileLocked erases the compact loading block before an event.
func (r *Renderer) clearVolatileLocked() {
	if clear := r.eraseVolatileLocked(); clear != "" {
		_, _ = fmt.Fprint(r.out, clear)
	}
}

// volatileAllowed reports whether carriage-return animation is appropriate:
// a real terminal that is not dumb or a CI runner, normal verbosity, and no
// dry run.
func (r *Renderer) volatileAllowed() bool {
	return r.term.Volatile && r.verbosity >= Normal && !r.dryRun
}

// ensureTickerLocked starts the animation tick while the volatile line is
// active. The goroutine exits through tickerStop or by noticing an empty
// progress tracker; stopping is clean either way.
func (r *Renderer) ensureTickerLocked() {
	if r.ticker != nil || !r.volatileAllowed() {
		return
	}
	interval := spinnerInterval
	if r.progress.spinner == SpinnerForge && r.term.Width >= 50 {
		interval = forgeAnimationInterval
	}
	ticker := time.NewTicker(interval)
	stop := make(chan struct{})
	r.ticker = ticker
	r.tickerStop = stop
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				r.mu.Lock()
				if !r.progress.running() {
					// Nothing left to animate: retire this goroutine.
					ticker.Stop()
					r.ticker, r.tickerStop = nil, nil
					r.mu.Unlock()
					return
				}
				r.redrawVolatileLocked()
				r.mu.Unlock()
			}
		}
	}()
}

// stopTickerLocked stops the animation goroutine.
func (r *Renderer) stopTickerLocked() {
	if r.tickerStop != nil {
		close(r.tickerStop)
	}
	if r.ticker != nil {
		r.ticker.Stop()
	}
	r.ticker, r.tickerStop = nil, nil
}

// syncTickerLocked stops the tick when nothing is running anymore.
func (r *Renderer) syncTickerLocked() {
	if r.ticker != nil && !r.progress.running() {
		r.stopTickerLocked()
	}
}
