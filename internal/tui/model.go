// Package tui renders scan events as an inline terminal log.
package tui

import (
	"slices"
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	"github.com/MikeRoss27/scanforge/internal/ui"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

const logWidth = 96

type scanFinishedMsg struct{}

type ScanModel struct {
	eventChan <-chan orchestrator.Event
	active    []string
	spin      spinner.Model
	started   time.Time
	width     int
	finished  bool
}

func NewScanModel(eventChan <-chan orchestrator.Event) ScanModel {
	return ScanModel{
		eventChan: eventChan,
		spin:      spinner.New(spinner.WithSpinner(spinner.MiniDot)),
		started:   time.Now(),
		width:     logWidth,
	}
}

func waitForEvent(ch <-chan orchestrator.Event) tea.Cmd {
	return func() tea.Msg {
		event, ok := <-ch
		if !ok {
			return scanFinishedMsg{}
		}
		return event
	}
}

func (m ScanModel) Init() tea.Cmd {
	return tea.Batch(m.spin.Tick, waitForEvent(m.eventChan))
}

func (m ScanModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case orchestrator.Event:
		switch event := msg.(type) {
		case orchestrator.WaveStartEvent:
			m.active = append([]string(nil), event.Modules...)
		case orchestrator.ModuleDoneEvent:
			if i := slices.Index(m.active, event.Name); i >= 0 {
				m.active = slices.Delete(m.active, i, i+1)
			}
		}
		next := waitForEvent(m.eventChan)
		if line := FormatEvent(msg); line != "" {
			// The print message must enter Bubble Tea before reading another
			// event, including the channel close that ends the program.
			return m, tea.Sequence(tea.Println(line), next)
		}
		return m, next
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd
	case scanFinishedMsg:
		m.finished = true
		return m, tea.Quit
	case tea.WindowSizeMsg:
		m.width = max(1, min(msg.Width, logWidth))
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.finished = true
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m ScanModel) View() string {
	if m.finished {
		return ""
	}
	status := "Preparing modules"
	if len(m.active) > 0 {
		status = "Running " + singleLine(strings.Join(m.active, ", "))
	}
	keys := ui.Secondary("Ctrl+C stop")
	elapsed := time.Since(m.started).Round(time.Second).String()
	prefix := ui.Primary(strings.TrimSpace(m.spin.View())) + " "
	suffix := "  " + ui.Secondary(elapsed) + "  " + keys

	available := m.width - ansi.StringWidth(prefix+suffix)
	if available < 10 {
		return ansi.Truncate(prefix+status, m.width, "…")
	}
	return prefix + ansi.Truncate(status, available, "…") + suffix
}
