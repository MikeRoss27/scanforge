package tui

import (
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	"github.com/MikeRoss27/scanforge/internal/ui"
	"github.com/charmbracelet/x/ansi"
)

// FormatEvent renders an event for the terminal log. Module start events are
// represented by the live status line or by the caller's verbose logging.
func FormatEvent(event orchestrator.Event) string {
	switch e := event.(type) {
	case orchestrator.WaveStartEvent:
		label := fmt.Sprintf("Wave %d", e.Wave)
		return "  " + ui.Primary("▸ "+label) + "  " + ui.Secondary(singleLine(strings.Join(e.Modules, ", ")))
	case orchestrator.ModuleDoneEvent:
		return formatModuleResult(e)
	case orchestrator.WarningEvent:
		return "  " + ui.Yellow("[WARN]") + " " + singleLine(e.Message)
	case orchestrator.DeadlockEvent:
		return "  " + ui.Red("[ERROR]") + " " + singleLine(e.Message)
	case orchestrator.FindingEvent:
		severity := strings.ToUpper(singleLine(e.Severity))
		if severity == "" {
			severity = "INFO"
		}
		line := "  " + "[" + ui.Severity(severity) + "]" + " " + ui.Bold(singleLine(e.Title))
		if e.Target != "" {
			line += "  " + ui.Secondary(singleLine(e.Target))
		}
		if e.Module != "" {
			line += "  " + ui.Secondary("("+singleLine(e.Module)+")")
		}
		return line
	default:
		return ""
	}
}

func formatModuleResult(e orchestrator.ModuleDoneEvent) string {
	mark, color, detail := "✓", ui.Green, singleLine(e.Summary)
	switch {
	case e.Status == "skipped":
		mark, color, detail = "↓", ui.Yellow, "skipped (dependency missing)"
	case e.Status == "aborted":
		mark, color, detail = "◌", ui.Orange, "aborted"
	case e.Failed:
		mark, color, detail = "✗", ui.Red, singleLine(e.Status)
		if detail == "" {
			detail = "failed"
		}
	}
	line := fmt.Sprintf("  %s %-14s", color(mark), singleLine(e.Name))
	if detail != "" {
		line += " " + color(detail)
	}
	if e.Dur > 0 {
		line += "  " + ui.Secondary(e.Dur.Round(time.Millisecond).String())
	}
	return strings.TrimRight(line, " ")
}

func singleLine(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, ansi.Strip(s))
}
