package console

import (
	"strings"
	"sync"
	"time"

	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	"github.com/charmbracelet/x/ansi"
)

// activeModule is one module currently running, with the last progress
// update it published ("" when the module does not emit metrics).
type activeModule struct {
	start     time.Time
	info      string
	updatedAt time.Time
}

// progressTracker holds the state behind the volatile progress line: which
// modules are running, when they started and any real progress they exposed.
// It never invents numbers: the line only shows what modules report.
type progressTracker struct {
	mu      sync.Mutex
	order   []string
	active  map[string]*activeModule
	spinner SpinnerStyle
}

func newProgressTracker(spinner SpinnerStyle) *progressTracker {
	return &progressTracker{
		active:  map[string]*activeModule{},
		spinner: spinner,
	}
}

func (p *progressTracker) start(name string, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.active[name]; ok {
		return
	}
	p.active[name] = &activeModule{start: now}
	p.order = append(p.order, name)
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

// update records a ModuleProgressEvent: a real count (current/total + unit)
// or a plain message published by the module itself.
func (p *progressTracker) update(e orchestrator.ModuleProgressEvent, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	m, ok := p.active[e.Name]
	if !ok {
		return
	}
	m.info = progressInfo(e)
	m.updatedAt = now
}

func progressInfo(e orchestrator.ModuleProgressEvent) string {
	if e.Total > 0 {
		current := e.Current
		if current < 0 {
			current = 0
		}
		if current > e.Total {
			current = e.Total
		}
		unit := strings.TrimSpace(e.Unit)
		if unit != "" {
			unit = " " + unit
		}
		return itoa(current) + "/" + itoa(e.Total) + unit
	}
	return strings.TrimSpace(e.Message)
}

// running reports whether any module is still active.
func (p *progressTracker) running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.active) > 0
}

// view renders the status text and real module counters. The renderer places
// it next to the generated forge sprite, or prefixes a classic spinner on
// terminals below 50 columns. All output is bounded by the available width.
func (p *progressTracker) view(now time.Time, width int, th theme) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.active) == 0 {
		return ""
	}

	var names []string
	var info string
	for _, name := range p.order {
		m := p.active[name]
		names = append(names, name)
		if m.info != "" && info == "" {
			info = m.info
		}
	}

	elapsed := formatElapsed(now.Sub(p.active[p.order[0]].start))
	prefix := p.spinner.styledFrame(now, th)
	if p.spinner == SpinnerForge && width >= 50 {
		prefix = ""
	}

	var text string
	if info != "" && len(p.order) == 1 {
		text = prefix + padName(p.order[0]) + info + " · " + elapsed
	} else {
		text = prefix + strings.Join(names, " · ")
		if elapsed != "" {
			text += " · " + elapsed
		}
	}
	return ansi.Truncate(text, max(10, width-1), "…")
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
