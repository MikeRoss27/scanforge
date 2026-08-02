package orchestrator

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/ui"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
)

// reporter surfaces module scheduling/execution progress to the terminal.
// Two implementations exist: a live one with a spinner per running module
// (interactive TTY, real runs) and a plain line-based one that degrades
// gracefully for dry runs, redirected output, and CI logs.
type reporter interface {
	waveStart(wave int, names []string)
	moduleStart(name string)
	moduleDone(name, status string, dur time.Duration, failed bool)
	deadlock(msg string)
	waveEnd()
	// close finalizes the reporter once the whole run has finished (all
	// waves done), flushing any live view before the caller prints the
	// closing summary.
	close()
}

// newReporter picks the live Bubble Tea UI for interactive, real
// (non-dry-run) runs, and falls back to plain lines otherwise — the live
// view writes cursor-control escape codes that only make sense on a real
// terminal, so anything else (dry-run previews, `> file`, CI logs) gets the
// plain reporter instead.
func newReporter(verbose, dryRun bool) reporter {
	if !dryRun && isInteractiveStdout() {
		return newSpinnerReporter()
	}
	return &lineReporter{verbose: verbose, alwaysLog: !dryRun}
}

func isInteractiveStdout() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// moduleState is the lifecycle of a single row in the live progress view.
type moduleState int

const (
	stateRunning moduleState = iota
	stateDone
)

type moduleRow struct {
	name   string
	state  moduleState
	start  time.Time
	status string
	dur    time.Duration
	failed bool
}

// spinnerReporter renders every module's progress as one continuously
// updating Bubble Tea view for the whole run, instead of tearing down and
// recreating a live area per DAG wave (which used to leave each wave's
// frame frozen into scrollback as duplicate-looking lines).
type spinnerReporter struct {
	program *tea.Program
	done    chan struct{}
}

func newSpinnerReporter() *spinnerReporter {
	m := newProgressModel()
	p := tea.NewProgram(m, tea.WithInput(nil), tea.WithoutSignalHandler())

	done := make(chan struct{})
	go func() {
		_, _ = p.Run()
		close(done)
	}()

	return &spinnerReporter{program: p, done: done}
}

func (r *spinnerReporter) waveStart(_ int, names []string) {
	r.program.Send(waveStartMsg{names: names})
}

func (r *spinnerReporter) moduleStart(string) {}

func (r *spinnerReporter) moduleDone(name, status string, dur time.Duration, failed bool) {
	r.program.Send(moduleDoneMsg{name: name, status: status, dur: dur, failed: failed})
}

func (r *spinnerReporter) deadlock(msg string) {
	r.program.Send(deadlockMsg(msg))
}

func (r *spinnerReporter) waveEnd() {}

func (r *spinnerReporter) close() {
	r.program.Quit()
	<-r.done
}

// progressModel is the Bubble Tea model backing spinnerReporter. All state
// mutation happens inside Update, which Bubble Tea guarantees runs on a
// single goroutine even though waveStart/moduleDone/deadlock are called
// concurrently from orchestrator wave goroutines — Program.Send is safe for
// that and simply queues the message.
type progressModel struct {
	order    []string
	rows     map[string]*moduleRow
	warnings []string
	spin     spinner.Model
}

func newProgressModel() *progressModel {
	s := spinner.New(spinner.WithSpinner(spinner.Dot))
	return &progressModel{
		rows: make(map[string]*moduleRow),
		spin: s,
	}
}

type waveStartMsg struct{ names []string }
type moduleDoneMsg struct {
	name   string
	status string
	dur    time.Duration
	failed bool
}
type deadlockMsg string

func (m *progressModel) Init() tea.Cmd { return nil }

func (m *progressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case waveStartMsg:
		wasIdle := !m.anyRunning()
		for _, name := range msg.names {
			m.order = append(m.order, name)
			m.rows[name] = &moduleRow{name: name, state: stateRunning, start: time.Now()}
		}
		if wasIdle && m.anyRunning() {
			return m, m.spin.Tick
		}
		return m, nil

	case moduleDoneMsg:
		if row, ok := m.rows[msg.name]; ok {
			row.state = stateDone
			row.status = msg.status
			row.dur = msg.dur
			row.failed = msg.failed
		}
		return m, nil

	case deadlockMsg:
		m.warnings = append(m.warnings, string(msg))
		return m, nil

	case spinner.TickMsg:
		if !m.anyRunning() {
			return m, nil
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *progressModel) View() string {
	var out string
	for _, name := range m.order {
		row := m.rows[name]
		switch row.state {
		case stateRunning:
			elapsed := time.Since(row.start).Round(time.Second)
			out += fmt.Sprintf("%s %s: running... (%s)\n", m.spin.View(), name, elapsed)
		case stateDone:
			label, tag := "SUCCESS", ui.SuccessTag
			if row.failed {
				label, tag = "ERROR", ui.ErrorTag
			}
			out += fmt.Sprintf("%s %s: %s (%s)\n", tag(label), name, row.status, row.dur.Round(time.Millisecond))
		}
	}
	for _, w := range m.warnings {
		out += ui.WarnTag("WARNING") + " " + w + "\n"
	}
	return out
}

func (m *progressModel) anyRunning() bool {
	for _, row := range m.rows {
		if row.state == stateRunning {
			return true
		}
	}
	return false
}

type lineReporter struct {
	verbose   bool
	alwaysLog bool
}

func (r *lineReporter) enabled() bool { return r.alwaysLog || r.verbose }

func (r *lineReporter) waveStart(wave int, names []string) {
	if !r.enabled() {
		return
	}
	ui.Info("Wave %d: %s", wave, strings.Join(names, ", "))
}

func (r *lineReporter) moduleStart(name string) {
	if !r.verbose {
		return
	}
	ui.Info("Running module %q...", name)
}

func (r *lineReporter) moduleDone(name, status string, dur time.Duration, failed bool) {
	if !r.enabled() {
		return
	}
	msg := fmt.Sprintf("%s: %s (%s)", name, status, dur.Round(time.Millisecond))
	if failed {
		ui.Error("%s", msg)
	} else {
		ui.Success("%s", msg)
	}
}

func (r *lineReporter) deadlock(msg string) {
	ui.Warn("%s", msg)
}

func (r *lineReporter) waveEnd() {}

func (r *lineReporter) close() {}
