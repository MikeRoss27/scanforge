package console

import (
	"strings"
	"sync"
	"time"

	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	"github.com/charmbracelet/x/ansi"
)

// activeModule is one module currently running, with the last progress
// update it published (zero values when the module does not emit metrics).
type activeModule struct {
	start time.Time

	// Last reported counter (Total > 0) and free-form message.
	current int
	total   int
	unit    string
	message string

	// First counter observation, the base of the ETA rate. The rate is
	// measured from the first update rather than the module start so a
	// slow warm-up (template loading, DNS) does not skew the estimate.
	firstAt      time.Time
	firstCurrent int
	updatedAt    time.Time
}

// progressTracker holds the state behind the volatile progress line: which
// modules are running, when they started and any real progress they exposed.
// It never invents numbers: the line only shows what modules report, plus an
// ETA extrapolated from the observed rate once there is enough signal.
type progressTracker struct {
	mu      sync.Mutex
	order   []string
	active  map[string]*activeModule
	spinner SpinnerStyle

	// expected is the number of modules the run selected (0 when unknown);
	// started counts modules that started so far. Together they tell when the
	// module on screen is really the last one, not just the only one running
	// while others wait for its output.
	expected int
	started  int
}

func newProgressTracker(spinner SpinnerStyle) *progressTracker {
	return &progressTracker{
		active:  map[string]*activeModule{},
		spinner: spinner,
	}
}

// setExpected records how many modules the run will execute.
func (p *progressTracker) setExpected(n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expected = n
}

func (p *progressTracker) start(name string, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.active[name]; ok {
		return
	}
	p.active[name] = &activeModule{start: now}
	p.order = append(p.order, name)
	p.started++
}

func (p *progressTracker) finish(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.active, name)
	for i, n := range p.order {
		if n == name {
			p.order = append(p.order[:i], p.order[i+1:]...)
			break
		}
	}
}

// update records a ModuleProgressEvent: a real count (current/total + unit),
// a plain message, or both, as published by the module itself.
func (p *progressTracker) update(e orchestrator.ModuleProgressEvent, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	m, ok := p.active[e.Name]
	if !ok {
		return
	}
	m.message = singleLine(strings.TrimSpace(e.Message))
	m.updatedAt = now
	if e.Total <= 0 {
		m.current, m.total, m.unit = 0, 0, ""
		return
	}
	current := min(max(e.Current, 0), e.Total)
	if m.firstAt.IsZero() || m.total != e.Total || current < m.current {
		// New or restarted counter (another pass, another total): the old
		// rate no longer applies.
		m.firstAt, m.firstCurrent = now, current
	}
	m.current, m.total, m.unit = current, e.Total, strings.TrimSpace(e.Unit)
}

// running reports whether any module is still active.
func (p *progressTracker) running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.active) > 0
}

// lastModuleLocked reports whether the single running module is the last
// one of the run: every selected module has started and only it remains.
func (p *progressTracker) lastModuleLocked() bool {
	return len(p.active) == 1 && p.expected > 1 && p.started >= p.expected
}

// view renders the status text and real module counters. The renderer places
// it next to the generated forge sprite, or prefixes a classic spinner on
// terminals below 50 columns. All output is bounded by the available width:
// optional parts (bar, message, ETA, "last module") are only added when they
// fit, in that order of priority.
func (p *progressTracker) view(now time.Time, width int, th theme) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.active) == 0 {
		return ""
	}

	elapsed := formatElapsed(now.Sub(p.active[p.order[0]].start))
	prefix := p.spinner.styledFrame(now, th)
	avail := max(10, width-1)
	if p.spinner == SpinnerForge && width >= 50 {
		prefix = ""
		// The renderer draws the forge sprite left of this text.
		avail = max(10, width-forgeWidth-3)
	}

	if len(p.order) > 1 {
		text := prefix + strings.Join(p.order, " · ")
		if elapsed != "" {
			text += " · " + elapsed
		}
		return ansi.Truncate(text, avail, "…")
	}

	name := p.order[0]
	m := p.active[name]
	b := lineBuilder{avail: avail}
	b.mandatory(prefix + padName(name))

	if m.total > 0 {
		b.mandatory(itoa(m.current) + "/" + itoa(m.total) + unitSuffix(m.unit))
		percent := m.current * 100 / m.total
		pct := " " + itoa(percent) + "%"
		bar := " " + progressBar(percent, th) + pct
		// We print our own percentage, so drop the module's copy to avoid
		// "34% · 34%".
		message := stripPercents(m.message)
		if message != "" {
			message = " · " + message
		}
		tail := " · " + elapsed
		// The module's message (matches, rate, phase) carries more than the
		// bar: show the bar only when everything else still fits next to it.
		if b.fits(bar + message + tail) {
			b.mandatory(bar + message)
		} else {
			b.optional(pct)
			if message != "" {
				b.optional(message)
			}
		}
		b.mandatory(tail)
		if eta := m.eta(now); eta > 0 {
			b.optional(" · ETA " + formatElapsed(eta))
		}
	} else {
		if m.message != "" {
			b.optional(m.message + " · ")
		}
		b.mandatory(elapsed)
	}
	if p.lastModuleLocked() {
		b.optional(" · " + th.Subtle("last module running"))
	}
	return ansi.Truncate(b.String(), avail, "…")
}

// eta extrapolates the remaining time from the rate observed since the first
// counter update. It returns 0 (no ETA shown) until there is enough signal:
// a few seconds of history and actual movement.
func (m *activeModule) eta(now time.Time) time.Duration {
	if m.total <= 0 || m.current >= m.total || m.firstAt.IsZero() {
		return 0
	}
	window := now.Sub(m.firstAt)
	done := m.current - m.firstCurrent
	if window < 5*time.Second || done <= 0 {
		return 0
	}
	remaining := time.Duration(float64(window) * float64(m.total-m.current) / float64(done))
	return remaining.Round(time.Second)
}

// lineBuilder assembles the volatile line within a width budget. Mandatory
// parts are always appended (the final Truncate bounds them); optional parts
// are appended only when they still fit.
type lineBuilder struct {
	strings.Builder
	avail int
	used  int
}

func (b *lineBuilder) mandatory(s string) {
	b.WriteString(s)
	b.used += ansi.StringWidth(s)
}

func (b *lineBuilder) optional(s string) bool {
	if !b.fits(s) {
		return false
	}
	b.mandatory(s)
	return true
}

// fits reports whether s can still be appended within the budget.
func (b *lineBuilder) fits(s string) bool {
	return b.used+ansi.StringWidth(s) <= b.avail
}

// progressBarCells is the width of the bar interior, kept small so the bar
// complements the counters instead of crowding them out.
const progressBarCells = 10

// progressBar renders a compact bar such as "▕████░░░░░░▏". Only the filled
// part is colored, so a colorless theme yields plain glyphs.
func progressBar(percent int, th theme) string {
	percent = min(max(percent, 0), 100)
	filled := percent * progressBarCells / 100
	return "▕" + th.Accent(strings.Repeat("█", filled)) +
		th.Dim(strings.Repeat("░", progressBarCells-filled)) + "▏"
}

// stripPercents removes standalone percentage tokens ("34%", "45.2%") from a
// " · "-separated progress message, dropping segments left empty.
func stripPercents(message string) string {
	if message == "" {
		return ""
	}
	var segments []string
	for _, segment := range strings.Split(message, "·") {
		var words []string
		for _, word := range strings.Fields(segment) {
			if !isPercent(word) {
				words = append(words, word)
			}
		}
		if len(words) > 0 {
			segments = append(segments, strings.Join(words, " "))
		}
	}
	return strings.Join(segments, " · ")
}

func isPercent(word string) bool {
	digits := strings.TrimSuffix(word, "%")
	if digits == word || digits == "" {
		return false
	}
	for _, r := range digits {
		if (r < '0' || r > '9') && r != '.' && r != ',' {
			return false
		}
	}
	return true
}

func unitSuffix(unit string) string {
	if unit == "" {
		return ""
	}
	return " " + unit
}

// padName aligns single-module progress lines with the module name column.
func padName(name string) string {
	pad := nameColumn - len([]rune(name))
	if pad < 1 {
		pad = 1
	}
	return name + strings.Repeat(" ", pad)
}

// formatElapsed renders the volatile line timer as mm:ss (h:mm:ss beyond an
// hour) without fractions, since it refreshes every tick anyway.
func formatElapsed(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	seconds := int(d.Seconds())
	mm := seconds / 60
	ss := seconds % 60
	if mm >= 60 {
		return itoa(mm/60) + ":" + twoDigits(mm%60) + ":" + twoDigits(ss)
	}
	return twoDigits(mm) + ":" + twoDigits(ss)
}

func twoDigits(n int) string {
	if n < 10 {
		return "0" + itoa(n)
	}
	return itoa(n)
}
