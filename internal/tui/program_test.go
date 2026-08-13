package tui

import (
	"testing"
	"time"

	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	tea "github.com/charmbracelet/bubbletea"
)

// Regression test: the TUI must exit by itself once the orchestrator closes
// the event channel. This used to hang until the user pressed q - waitForEvent
// returned nil on channel close, and Bubble Tea drops nil command results.
func TestProgramAutoQuitsOnChannelClose(t *testing.T) {
	ch := make(chan orchestrator.Event)
	go func() {
		ch <- orchestrator.WaveStartEvent{Wave: 1, Modules: []string{"nuclei"}}
		ch <- orchestrator.ModuleDoneEvent{Name: "nuclei", Status: "completed"}
		time.Sleep(50 * time.Millisecond)
		close(ch)
	}()

	done := make(chan struct{})
	go func() {
		_, err := tea.NewProgram(NewScanModel(ch), tea.WithInput(nil), tea.WithoutRenderer()).Run()
		if err != nil {
			t.Errorf("program error: %v", err)
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("TUI did not quit after the event channel closed (scan completed)")
	}
}
