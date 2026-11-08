// Package tui renders the live scan progress view with Bubble Tea.
//
// Layout follows lazygit/k9s: separate bordered panes for distinct regions
// (modules, findings, log) instead of one big frame around everything or a
// single wide table. The box is reserved for those functional panes; the top
// status line and the footer are plain text, matching the flat, unboxed
// style the rest of the CLI (internal/ui.Section) uses for one-shot output.
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
)

// sideBySideWidth is the terminal width above which the modules and
// findings panes sit next to each other; below it they stack vertically so
// narrow SSH sessions still get a readable layout instead of two
// unreadably-thin columns.
const sideBySideWidth = 90

// defaultWidth is used before the first tea.WindowSizeMsg arrives.
const defaultWidth = 100

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

// maxWarningsShown bounds the live log pane the same way; the full list is
// still replayed by the CLI after the TUI exits.
const maxWarningsShown = 5

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
	target        string
	profile       string
	order         []string
	rows          map[string]*moduleRow
	warnings      []string
	findings      []findingRow
	findingsTotal int
	spin          spinner.Model
	started       time.Time
	width         int
}

func NewScanModel(eventChan <-chan orchestrator.Event, target, profile string) ScanModel {
	s := spinner.New(spinner.WithSpinner(spinner.MiniDot))
	s.Style = lipgloss.NewStyle().Foreground(ui.Accent).Bold(true)

	return ScanModel{
		eventChan: eventChan,
		target:    target,
		profile:   profile,
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
			// they stay visible instead of vanishing from the pane.
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

	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m ScanModel) View() string {
	width := m.width
	if width <= 0 {
		width = defaultWidth
	}

	var out strings.Builder

	// Top status line — plain text, no border; the box is reserved for the
	// panes below, where it marks a real functional region.
	left := ui.Bold("SCANFORGE")
	if m.target != "" {
		left += "  " + ui.Dim(m.target)
	}
	if m.profile != "" {
		left += "  " + ui.Secondary(m.profile)
	}
	right := ui.Dim(time.Since(m.started).Round(time.Second).String())
	out.WriteString(ui.Justify(left, right, width) + "\n\n")

	modulesPane := m.renderModulesPane(width)
	findingsPane := m.renderFindingsPane(width)
	if width >= sideBySideWidth {
		out.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, modulesPane, " ", findingsPane) + "\n")
	} else {
		out.WriteString(modulesPane + "\n" + findingsPane + "\n")
	}

	if len(m.warnings) > 0 {
		out.WriteString(m.renderLogPane(width) + "\n")
	}

	// Footer: progress on the left, key hints on the right, both plain text.
	completed, failed, skipped := m.tally()
	var progress string
	if len(m.order) > 0 {
		progress = ui.ProgressBar(completed, len(m.order), 20) + " " + ui.Dim(fmt.Sprintf("%d completed", completed))
		if failed > 0 {
			progress += ui.Dim(" · ") + ui.Red(fmt.Sprintf("%d failed", failed))
		}
		if skipped > 0 {
			progress += ui.Dim(" · ") + ui.Yellow(fmt.Sprintf("%d skipped/aborted", skipped))
		}
	}
	help := ui.Dim("q: quit  ·  ctrl+c: abort")
	out.WriteString("\n" + ui.Justify(progress, help, width))

	return out.String()
}

// paneBorderOverhead is how many columns a pane's own border (1 each side)
// and padding (Padding(0,1), 1 each side) add on top of its text content.
const paneBorderOverhead = 4

// paneWidths returns the text content width (what the pane's own content
// lines should be built to — border and padding are added on top by
// renderPane) for the modules pane and the findings pane, side by side.
func paneWidths(width int) (modulesText, findingsText int) {
	const gap = 1 // the " " between the two JoinHorizontal'd panes
	avail := width - gap - 2*paneBorderOverhead
	if avail < 40 {
		avail = 40
	}
	modulesText = avail * 45 / 100
	findingsText = avail - modulesText
	if modulesText < 20 {
		modulesText = 20
	}
	if findingsText < 20 {
		findingsText = 20
	}
	return modulesText, findingsText
}

// renderPane wraps body (already laid out to exactly textWidth columns per
// line) in a rounded border with the given accent. textWidth is the pane's
// content width; lipgloss.Style.Width wants that plus the pane's own
// padding (border is added on top again by Render).
func renderPane(title string, titleColor lipgloss.Color, border lipgloss.Color, body string, textWidth int) string {
	var b strings.Builder
	b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(titleColor).Render(title) + "\n")
	b.WriteString(ui.Dim(strings.Repeat("─", max(textWidth, 1))) + "\n")
	b.WriteString(body)

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(border).
		Padding(0, 1).
		Width(textWidth + 2).
		Render(b.String())
}

func (m ScanModel) renderModulesPane(width int) string {
	textWidth, _ := paneWidths(width)
	if width < sideBySideWidth {
		textWidth = width - paneBorderOverhead
	}

	var body string
	if len(m.order) == 0 {
		body = ui.Dim("Waiting for modules to load...")
	} else {
		lines := make([]string, 0, len(m.order))
		for _, name := range m.order {
			lines = append(lines, m.moduleLine(m.rows[name], textWidth))
		}
		body = strings.Join(lines, "\n")
	}

	return renderPane("● MODULES", ui.Accent, ui.Accent, body, textWidth)
}

// moduleLine renders one module as a status glyph + name on the left and a
// duration/status word right-aligned, e.g. "✓ subfinder        2.1s" — no
// separate state/status columns, matching the compact lazygit-style row.
func (m ScanModel) moduleLine(row *moduleRow, innerWidth int) string {
	var mark, name, right string
	switch {
	case row.state == stateRunning:
		mark, name, right = m.spin.View(), ui.Bold(row.name), ui.Primary("running")
	case row.failed:
		mark, name, right = ui.Red("✗"), ui.Bold(row.name), ui.Red(orDefault(row.status, "failed"))
	case row.status == "skipped":
		mark, name, right = ui.Dim("·"), ui.Dim(row.name), ui.Dim("skipped")
	case row.status == "aborted":
		mark, name, right = ui.Orange("◌"), ui.Dim(row.name), ui.Orange("aborted")
	default:
		mark, name, right = ui.Green("✓"), ui.Bold(row.name), ui.Dim(row.dur.Round(time.Millisecond).String())
	}
	left := mark + " " + name
	if row.summary != "" && row.state == stateDone && !row.failed {
		right = ui.Dim(row.dur.Round(time.Millisecond).String()) + "  " + ui.Secondary(row.summary)
	}
	return ui.Justify(left, right, innerWidth)
}

func (m ScanModel) renderFindingsPane(width int) string {
	_, textWidth := paneWidths(width)
	if width < sideBySideWidth {
		textWidth = width - paneBorderOverhead
	}

	header := "FINDINGS"
	if m.findingsTotal > 0 {
		header += fmt.Sprintf(" (%d)", m.findingsTotal)
	}

	var body string
	if len(m.findings) == 0 {
		body = ui.Dim("No findings yet")
	} else {
		var lines []string
		for _, f := range m.findings {
			sev := orDefault(f.severity, "info")
			lines = append(lines, truncate(ui.Severity(strings.ToUpper(sev))+"  "+ui.Text(f.title), textWidth))
			if f.target != "" {
				lines = append(lines, ui.Dim(truncate(f.target, textWidth)))
			}
		}
		if m.findingsTotal > len(m.findings) {
			lines = append(lines, ui.Dim(fmt.Sprintf("… showing last %d", len(m.findings))))
		}
		body = strings.Join(lines, "\n")
	}

	return renderPane(header, ui.Dimmed, ui.BorderColor, body, textWidth)
}

func (m ScanModel) renderLogPane(width int) string {
	textWidth := width - paneBorderOverhead
	if textWidth < 1 {
		textWidth = 1
	}

	shown := m.warnings
	if len(shown) > maxWarningsShown {
		shown = shown[len(shown)-maxWarningsShown:]
	}

	header := "LOG"
	if len(m.warnings) > len(shown) {
		header += fmt.Sprintf(" (%d total · last %d)", len(m.warnings), len(shown))
	}

	var lines []string
	for _, w := range shown {
		lines = append(lines, ui.Yellow(truncate(w, textWidth)))
	}

	return renderPane(header, ui.Dimmed, ui.BorderColor, strings.Join(lines, "\n"), textWidth)
}

func truncate(s string, width int) string {
	if width <= 1 || lipgloss.Width(s) <= width {
		return s
	}
	runes := []rune(s)
	if width-1 >= len(runes) {
		return s
	}
	return string(runes[:width-1]) + "…"
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
