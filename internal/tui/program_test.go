package tui

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

// Even a burst followed immediately by channel close must remain in scrollback.
func TestProgramPrintsEventsInOrderAndQuits(t *testing.T) {
	events := []orchestrator.Event{
		orchestrator.WaveStartEvent{Wave: 1, Modules: []string{"alpha"}},
		orchestrator.FindingEvent{Module: "alpha", Severity: "medium", Title: "example finding"},
		orchestrator.WarningEvent{Message: "example warning"},
		orchestrator.ModuleDoneEvent{Name: "alpha", Status: "completed", Summary: "module finished"},
	}
	ch := make(chan orchestrator.Event, len(events))
	for _, event := range events {
		ch <- event
	}
	close(ch)

	var out bytes.Buffer
	result := make(chan error, 1)
	program := tea.NewProgram(NewScanModel(ch), tea.WithInput(nil), tea.WithOutput(&out))
	go func() {
		_, err := program.Run()
		result <- err
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		program.Kill()
		t.Fatal("program did not quit after the event channel closed")
	}

	log := out.String()
	t.Log("\n" + strings.TrimRight(strings.ReplaceAll(ansi.Strip(log), "\r", ""), " \n"))
	if strings.Contains(log, "\x1b[?1049h") {
		t.Fatal("program entered the alternate screen")
	}
	remaining := log
	for _, text := range []string{"Wave 1", "example finding", "example warning", "module finished"} {
		_, rest, ok := strings.Cut(remaining, text)
		if !ok {
			t.Fatalf("%q missing or out of order in %q", text, log)
		}
		remaining = rest
	}
}
