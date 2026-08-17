// Package tui renders the live scan progress view with Bubble Tea.
package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	"github.com/MikeRoss27/scanforge/internal/ui"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
)

var (
	borderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ui.BorderColor).
			Padding(1, 2)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ui.Accent)

	rowStyle = lipgloss.NewStyle().Padding(0, 1)

	warnStyle = lipgloss.NewStyle().
			Foreground(ui.AccentOrange).
			Bold(true)
)

type moduleState int

const (
	stateRunning moduleState = iota
	stateDone
)

type moduleRow struct {
	name    string
	state   moduleState
	start   time.Time
	status  string
	dur     time.Duration
	failed  bool
	summary string
}

// maxFindingsShown bounds the live findings feed to the most recent hits so
// a noisy scan (hundreds of nuclei matches) doesn't blow out the terminal.
const maxFindingsShown = 8

// scanFinishedMsg is delivered when the orchestrator closes the event
// channel. It must be a typed message rather than a nil msg: Bubble Tea
// drops nil command results (tea.go filters `msg == nil`), so a nil would
// silently never reach Update and the TUI would hang after the scan ends.
type scanFinishedMsg struct{}

type findingRow struct {
	module   string
	severity string
	title    string
	target   string
}

type ScanModel struct {
	eventChan     <-chan orchestrator.Event
	order         []string
	rows          map[string]*moduleRow
	warnings      []string
	findings      []findingRow
	findingsTotal int
	spin          spinner.Model
	started       time.Time
}

func NewScanModel(eventChan <-chan orchestrator.Event) ScanModel {
	s := spinner.New(spinner.WithSpinner(spinner.MiniDot))
	s.Style = lipgloss.NewStyle().Foreground(ui.Accent).Bold(true)

	return ScanModel{
		eventChan: eventChan,
		rows:      make(map[string]*moduleRow),
		spin:      s,
		started:   time.Now(),
	}
}

// Warnings returns the warnings collected while the TUI was live, so the CLI
// can replay them once the scan view is gone.
func (m ScanModel) Warnings() []string {
	return m.warnings
}

func waitForEvent(ch <-chan orchestrator.Event) tea.Cmd {
	return func() tea.Msg {
		event, ok := <-ch
		if !ok {
			return scanFinishedMsg{} // channel closed: scan finished
		}
		return event
	}
}

func (m ScanModel) Init() tea.Cmd {
	return tea.Batch(
		m.spin.Tick,
		waitForEvent(m.eventChan),
	)
}

func (m ScanModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case orchestrator.WaveStartEvent:
		wasIdle := !m.anyRunning()
		for _, name := range msg.Modules {
			m.order = append(m.order, name)
			m.rows[name] = &moduleRow{name: name, state: stateRunning, start: time.Now()}
		}
		var cmd tea.Cmd
		if wasIdle && m.anyRunning() {
			cmd = m.spin.Tick
		}
		return m, tea.Batch(cmd, waitForEvent(m.eventChan))

	case orchestrator.ModuleStartEvent:
		return m, waitForEvent(m.eventChan)

	case orchestrator.ModuleDoneEvent:
		row, ok := m.rows[msg.Name]
		if !ok {
			// Modules skipped by a failed dependency (or stopped by an
			// abort) never had a WaveStartEvent; create their row now so
			// they stay visible instead of vanishing from the table.
			m.order = append(m.order, msg.Name)
			row = &moduleRow{name: msg.Name}
			m.rows[msg.Name] = row
		}
		row.state = stateDone
		row.status = msg.Status
		row.dur = msg.Dur
		row.failed = msg.Failed
		row.summary = msg.Summary
		return m, waitForEvent(m.eventChan)

	case orchestrator.DeadlockEvent:
		m.warnings = append(m.warnings, msg.Message)
		return m, waitForEvent(m.eventChan)

	case orchestrator.WarningEvent:
		m.warnings = append(m.warnings, msg.Message)
		return m, waitForEvent(m.eventChan)

	case orchestrator.FindingEvent:
		m.findingsTotal++
		m.findings = append(m.findings, findingRow{
			module:   msg.Module,
			severity: msg.Severity,
			title:    msg.Title,
			target:   msg.Target,
		})
		if len(m.findings) > maxFindingsShown {
			m.findings = m.findings[len(m.findings)-maxFindingsShown:]
		}
		return m, waitForEvent(m.eventChan)

	case spinner.TickMsg:
		if !m.anyRunning() {
			return m, nil
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case scanFinishedMsg:
		return m, tea.Quit

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m ScanModel) View() string {
	var out strings.Builder

	// Top banner with the brand gradient and a live run timer on the right.
	banner := ui.Gradient("SCANFORGE ORCHESTRATOR", ui.AccentCyan, ui.AccentMagenta)
	elapsed := ui.Dim("⏱ " + time.Since(m.started).Round(time.Second).String())
	out.WriteString(ui.Bold(banner) + "  " + elapsed + "\n")
	out.WriteString(ui.Dim(strings.Repeat("─", lipgloss.Width(banner))) + "\n\n")

	// The table
	if len(m.order) > 0 {
		t := table.New().
			Border(lipgloss.HiddenBorder()).
			Headers("MODULE", "STATE", "TIME", "STATUS").
			StyleFunc(func(row, col int) lipgloss.Style {
				if row == table.HeaderRow {
					return headerStyle.Padding(0, 2)
				}
				return rowStyle.Padding(0, 2)
			})

		for _, name := range m.order {
			row := m.rows[name]
			if row.state == stateRunning {
				elapsed := time.Since(row.start).Round(time.Second).String()
				t.Row(ui.Bold(name), ui.Primary(m.spin.View()+" RUNNING"), ui.Dim(elapsed), ui.Dim("..."))
				continue
			}

			stateLabel := ui.SuccessTag("DONE")
			statusText := ui.Green(row.status)
			dur := ui.Dim(row.dur.Round(time.Millisecond).String())
			switch {
			case row.failed:
				stateLabel = ui.ErrorTag("FAIL")
				statusText = ui.Red(row.status)
			case row.status == "skipped":
				stateLabel = ui.SkipTag("SKIP")
				statusText = ui.Dim("dependency missing")
				dur = ui.Dim("–")
			case row.status == "aborted":
				stateLabel = ui.AbortTag("ABORT")
				statusText = ui.Orange("aborted")
				dur = ui.Dim("–")
			}
			if row.summary != "" {
				statusText += ui.Secondary(" · " + row.summary)
			}

			t.Row(ui.Bold(name), stateLabel, dur, statusText)
		}

		out.WriteString(t.Render())
		out.WriteString("\n")
	} else {
		out.WriteString(ui.Dim("  Waiting for modules to load...") + "\n")
	}

	// Warnings panel
	if len(m.warnings) > 0 {
		var warnBox strings.Builder
		for _, w := range m.warnings {
			warnBox.WriteString("⚠ " + w + "\n")
		}
		out.WriteString("\n")
		out.WriteString(warnStyle.Render(warnBox.String()))
	}

	// Live findings feed
	if len(m.findings) > 0 {
		var box strings.Builder
		for _, f := range m.findings {
			sev := orDefault(f.severity, "info")
			line := ui.Severity(strings.ToUpper(sev))
			line += " " + ui.Bold(f.title)
			if f.target != "" {
				line += ui.Dim(" · " + f.target)
			}
			line += ui.Dim(" (" + f.module + ")")
			box.WriteString("  " + line + "\n")
		}
		header := ui.DimBold("FINDINGS") + ui.Dim(fmt.Sprintf(" (%d)", m.findingsTotal))
		if m.findingsTotal > len(m.findings) {
			header += ui.Dim(fmt.Sprintf(" · showing last %d", len(m.findings)))
		}
		out.WriteString("\n")
		out.WriteString(header + "\n")
		out.WriteString(box.String())
	}

	// Progress: the bar counts successful completions against every module
	// of the run (including skipped ones), so a partially failed pipeline
	// never shows a misleading full bar.
	completed, failed, skipped := m.tally()
	if len(m.order) > 0 {
		out.WriteString("\n")
		out.WriteString(ui.DimBold("PROGRESS") + "  " + ui.ProgressBar(completed, len(m.order), 24))
		out.WriteString("  " + ui.Dim(fmt.Sprintf("%d completed", completed)))
		if failed > 0 {
			out.WriteString(ui.Dim(" · ") + ui.Red(fmt.Sprintf("%d failed", failed)))
		}
		if skipped > 0 {
			out.WriteString(ui.Dim(" · ") + ui.Yellow(fmt.Sprintf("%d skipped/aborted", skipped)))
		}
	}

	// Footer
	out.WriteString("\n\n")
	out.WriteString(ui.Dim("q: quit  •  ctrl+c: abort"))

	// Wrap in a glowing border
	return borderStyle.Render(out.String()) + "\n"
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func (m ScanModel) anyRunning() bool {
	for _, row := range m.rows {
		if row.state == stateRunning {
			return true
		}
	}
	return false
}

// tally counts finished modules by outcome so the progress line can report
// completions, failures and skips separately instead of one blended number.
func (m ScanModel) tally() (completed, failed, skipped int) {
	for _, row := range m.rows {
		if row.state != stateDone {
			continue
		}
		switch {
		case row.failed:
			failed++
		case row.status == "skipped", row.status == "aborted":
			skipped++
		default:
			completed++
		}
	}
	return completed, failed, skipped
}
