package tui

import (
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

func TestViewTracksRunningModules(t *testing.T) {
	model := NewScanModel(nil)
	if !strings.Contains(model.View(), "Preparing modules") {
		t.Fatalf("unexpected initial view: %q", model.View())
	}

	next, _ := model.Update(orchestrator.WaveStartEvent{Wave: 1, Modules: []string{"alpha", "beta"}})
	if !strings.Contains(next.View(), "Running alpha, beta") {
		t.Fatalf("wave modules missing from view: %q", next.View())
	}

	next, _ = next.Update(orchestrator.ModuleDoneEvent{Name: "alpha", Status: "completed"})
	if view := next.View(); strings.Contains(view, "alpha") || !strings.Contains(view, "Running beta") {
		t.Fatalf("unexpected view after module completion: %q", view)
	}
}

func TestViewStaysOnOneLineAtAnyWidth(t *testing.T) {
	model := NewScanModel(nil)
	active, _ := model.Update(orchestrator.WaveStartEvent{
		Wave: 1, Modules: []string{strings.Repeat("界", 70) + "\nnext"},
	})
	for _, width := range []int{1, 12, 32, 96, 240} {
		resized, _ := active.Update(tea.WindowSizeMsg{Width: width})
		view := resized.View()
		if ansi.StringWidth(view) > min(width, logWidth) || strings.Contains(view, "\n") {
			t.Errorf("view overflows at %d columns: %q", width, view)
		}
	}
}

func TestUpdateQuitKeys(t *testing.T) {
	for _, key := range []tea.KeyMsg{
		{Type: tea.KeyCtrlC},
		{Type: tea.KeyRunes, Runes: []rune("q")},
	} {
		updated, cmd := NewScanModel(nil).Update(key)
		if cmd == nil || cmd() != tea.Quit() {
			t.Errorf("%s did not quit", key)
		}
		if text := updated.View(); text != "" {
			t.Errorf("status still visible after %s: %q", key, text)
		}
	}
}
