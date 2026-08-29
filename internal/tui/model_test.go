package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	tea "github.com/charmbracelet/bubbletea"
)

func updateModel(t *testing.T, m ScanModel, msg tea.Msg) (ScanModel, tea.Cmd) {
	t.Helper()
	updated, cmd := m.Update(msg)
	model, ok := updated.(ScanModel)
	if !ok {
		t.Fatalf("expected ScanModel, got %T", updated)
	}
	return model, cmd
}

func TestNewScanModel(t *testing.T) {
	ch := make(chan orchestrator.Event)
	m := NewScanModel(ch, "example.com", "web")

	if m.eventChan != ch {
		t.Error("expected event channel to be stored")
	}
	if m.target != "example.com" {
		t.Errorf("expected target %q, got %q", "example.com", m.target)
	}
	if m.profile != "web" {
		t.Errorf("expected profile %q, got %q", "web", m.profile)
	}
	if m.rows == nil {
		t.Fatal("expected non-nil rows map")
	}
	if len(m.order) != 0 {
		t.Errorf("expected empty order, got %v", m.order)
	}
	if len(m.warnings) != 0 {
		t.Errorf("expected no warnings, got %v", m.warnings)
	}
}

func TestUpdateWaveStartCreatesRows(t *testing.T) {
	m := NewScanModel(make(chan orchestrator.Event), "", "")

	model, _ := updateModel(t, m, orchestrator.WaveStartEvent{Wave: 1, Modules: []string{"subfinder", "dnsx"}})

	if len(model.order) != 2 {
		t.Errorf("expected 2 modules in order, got %v", model.order)
	}
	if model.order[0] != "subfinder" || model.order[1] != "dnsx" {
		t.Errorf("unexpected order: %v", model.order)
	}
	for _, name := range model.order {
		row, ok := model.rows[name]
		if !ok {
			t.Fatalf("expected row for %q", name)
		}
		if row.name != name {
			t.Errorf("expected row name %q, got %q", name, row.name)
		}
		if row.state != stateRunning {
			t.Errorf("expected row %q running, got state %d", name, row.state)
		}
	}
	if !model.anyRunning() {
		t.Error("expected model to be running")
	}
}

func TestUpdateModuleDoneMarksRow(t *testing.T) {
	m, _ := updateModel(t, NewScanModel(make(chan orchestrator.Event), "", ""), orchestrator.WaveStartEvent{Wave: 1, Modules: []string{"nuclei"}})

	model, _ := updateModel(t, m, orchestrator.ModuleDoneEvent{
		Name: "nuclei", Status: "completed", Dur: 3 * time.Second, Failed: false, Summary: "2 findings",
	})

	row := model.rows["nuclei"]
	if row == nil {
		t.Fatal("expected row for nuclei")
	}
	if row.state != stateDone {
		t.Errorf("expected state done, got %d", row.state)
	}
	if row.status != "completed" {
		t.Errorf("expected status %q, got %q", "completed", row.status)
	}
	if row.dur != 3*time.Second {
		t.Errorf("expected dur 3s, got %v", row.dur)
	}
	if row.failed {
		t.Error("expected not failed")
	}
	if row.summary != "2 findings" {
		t.Errorf("expected summary %q, got %q", "2 findings", row.summary)
	}
	if model.anyRunning() {
		t.Error("expected no running rows after all modules done")
	}
}

// Modules skipped by a failed dependency never receive a WaveStartEvent; the
// orchestrator only sends their ModuleDoneEvent. The TUI must materialize the
// row on that event instead of silently dropping the module.
func TestUpdateModuleDoneCreatesRowForNeverStartedModule(t *testing.T) {
	m := NewScanModel(make(chan orchestrator.Event), "", "")
	model, _ := updateModel(t, m, orchestrator.ModuleDoneEvent{Name: "nmap", Status: "skipped"})

	if len(model.order) != 1 || model.order[0] != "nmap" {
		t.Fatalf("expected a row for nmap, got %v", model.order)
	}
	row := model.rows["nmap"]
	if row == nil {
		t.Fatal("expected row entry for nmap")
	}
	if row.state != stateDone {
		t.Errorf("expected state done, got %d", row.state)
	}
	if row.status != "skipped" {
		t.Errorf("expected status skipped, got %q", row.status)
	}
}

func TestUpdateDeadlockAppendsWarning(t *testing.T) {
	m := NewScanModel(make(chan orchestrator.Event), "", "")
	model, _ := updateModel(t, m, orchestrator.DeadlockEvent{Message: "deadlock detected"})
	if len(model.warnings) != 1 {
		t.Fatalf("expected 1 warning, got %v", model.warnings)
	}
	if model.warnings[0] != "deadlock detected" {
		t.Errorf("unexpected warning %q", model.warnings[0])
	}
}

func TestUpdateModuleWarningAppendsWarning(t *testing.T) {
	m := NewScanModel(make(chan orchestrator.Event), "", "")
	model, _ := updateModel(t, m, orchestrator.WarningEvent{Message: "jssecrets: 0 JS files"})
	if len(model.warnings) != 1 {
		t.Fatalf("expected 1 warning, got %v", model.warnings)
	}
	if model.warnings[0] != "jssecrets: 0 JS files" {
		t.Errorf("unexpected warning %q", model.warnings[0])
	}
}

func TestUpdateQuitKeys(t *testing.T) {
	tests := []struct {
		name string
		msg  tea.Msg
	}{
		{name: "ctrl+c", msg: tea.KeyMsg{Type: tea.KeyCtrlC}},
		{name: "q", msg: tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewScanModel(make(chan orchestrator.Event), "", "")
			model, cmd := updateModel(t, m, tt.msg)
			if len(model.order) != 0 {
				t.Errorf("expected unchanged model, got %v", model.order)
			}
			if cmd == nil {
				t.Fatal("expected quit command")
			}
			if msg := cmd(); msg != tea.Quit() {
				t.Errorf("expected tea.Quit, got %v", msg)
			}
		})
	}
}

func TestUpdateClosedChannelQuits(t *testing.T) {
	ch := make(chan orchestrator.Event)
	close(ch)
	m := NewScanModel(ch, "", "")

	model, cmd := updateModel(t, m, scanFinishedMsg{})
	if len(model.order) != 0 {
		t.Errorf("expected unchanged model, got %v", model.order)
	}
	if cmd == nil {
		t.Fatal("expected quit command")
	}
	if msg := cmd(); msg != tea.Quit() {
		t.Errorf("expected tea.Quit, got %v", msg)
	}
}

func TestInitStartsSpinnerAndWaits(t *testing.T) {
	ch := make(chan orchestrator.Event)
	m := NewScanModel(ch, "", "")

	cmd := m.Init()
	if cmd == nil {
		t.Fatal("expected a command from Init")
	}
}

func TestViewRendersProgress(t *testing.T) {
	m := NewScanModel(make(chan orchestrator.Event), "", "")
	m, _ = updateModel(t, m, orchestrator.WaveStartEvent{Wave: 1, Modules: []string{"subfinder"}})
	m, _ = updateModel(t, m, orchestrator.ModuleDoneEvent{Name: "subfinder", Status: "completed", Dur: time.Second, Summary: "3 hosts"})

	view := m.View()
	for _, want := range []string{"subfinder", "DONE", "PROGRESS", "q: quit"} {
		if !strings.Contains(view, want) {
			t.Errorf("expected view to contain %q, got:\n%s", want, view)
		}
	}
}

func TestViewShowsWarning(t *testing.T) {
	m := NewScanModel(make(chan orchestrator.Event), "", "")
	m, _ = updateModel(t, m, orchestrator.DeadlockEvent{Message: "wave stalled"})

	view := m.View()
	if !strings.Contains(view, "wave stalled") {
		t.Errorf("expected view to contain warning, got:\n%s", view)
	}
}

func TestViewShowsSkippedModulesWithOwnBadgeAndTally(t *testing.T) {
	m := NewScanModel(make(chan orchestrator.Event), "", "")
	m, _ = updateModel(t, m, orchestrator.WaveStartEvent{Wave: 1, Modules: []string{"subfinder", "naabu"}})
	m, _ = updateModel(t, m, orchestrator.ModuleDoneEvent{Name: "subfinder", Status: "completed", Dur: time.Second})
	m, _ = updateModel(t, m, orchestrator.ModuleDoneEvent{Name: "naabu", Status: "failed", Failed: true, Dur: time.Second})
	// nmap never started: only its done event arrives.
	m, _ = updateModel(t, m, orchestrator.ModuleDoneEvent{Name: "nmap", Status: "skipped"})

	view := m.View()
	for _, want := range []string{"nmap", "SKIP", "1 completed", "1 failed", "1 skipped/aborted"} {
		if !strings.Contains(view, want) {
			t.Errorf("expected view to contain %q, got:\n%s", want, view)
		}
	}
}

func TestViewFindingsHeaderCountsAllFindings(t *testing.T) {
	m := NewScanModel(make(chan orchestrator.Event), "", "")
	for i := 0; i < maxFindingsShown+3; i++ {
		m, _ = updateModel(t, m, orchestrator.FindingEvent{
			Module: "nuclei", Severity: "high", Title: "finding", Target: "https://example.com",
		})
	}

	view := m.View()
	if !strings.Contains(view, "(11)") {
		t.Errorf("expected findings total (11) in header, got:\n%s", view)
	}
	if !strings.Contains(view, "showing last") {
		t.Errorf("expected truncation hint, got:\n%s", view)
	}
}

func TestAnyRunning(t *testing.T) {
	m := NewScanModel(make(chan orchestrator.Event), "", "")
	if m.anyRunning() {
		t.Error("expected no running rows initially")
	}
	m, _ = updateModel(t, m, orchestrator.WaveStartEvent{Wave: 1, Modules: []string{"a"}})
	if !m.anyRunning() {
		t.Error("expected running rows after wave start")
	}
}
