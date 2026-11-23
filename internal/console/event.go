package console

import (
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	"github.com/MikeRoss27/scanforge/internal/runner"
	"github.com/charmbracelet/x/ansi"
)

// nameColumn is the width reserved for module names on lifecycle lines.
// Long module names simply overflow into the detail column rather than
// breaking the layout on narrow terminals.
const nameColumn = 15

// detailColumn is where the detail text starts on completion lines; the
// duration follows after a fixed gap so completions read as columns without
// being a rigid table.
const detailColumn = 32

// formatDuration renders a module duration the way scanners do: seconds
// with one decimal below a minute, mm:ss up to an hour, h:mm:ss above.
func formatDuration(d time.Duration) string {
	switch {
	case d <= 0:
		return ""
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	case d < time.Hour:
		return fmt.Sprintf("%02d:%02d", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%d:%02d:%02d", int(d.Hours()), int(d.Minutes())%60, int(d.Seconds())%60)
	}
}

// eventLine renders one timestamped, tagged log line.
func (r *Renderer) eventLine(tag, message string) string {
	return r.th.timestamp(r.stamp()) + " " + r.th.tag(tag) + " " + message
}

// stamp returns the current clock formatted as HH:MM:SS.
func (r *Renderer) stamp() string {
	return r.clock().Format("15:04:05")
}

// lifecycleLine renders a module start/completion line with adaptive
// columns: name column, detail column, duration.
func (r *Renderer) lifecycleLine(tag, name, detail string, dur time.Duration) string {
	line := r.eventLine(tag, r.th.Bold(name))
	rest := ""
	if detail != "" {
		rest += detail
	}
	if d := formatDuration(dur); d != "" {
		if rest != "" {
			rest += "  "
		}
		rest += r.th.Dim(d)
	}
	if rest == "" {
		return line
	}
	// Pad the name so details align, but never let the padding push
	// content through the right edge of a narrow terminal.
	pad := nameColumn - len([]rune(name))
	if pad < 1 {
		pad = 1
	}
	if r.term.Width < 60 {
		pad = 1
	}
	return line + strings.Repeat(" ", pad) + rest
}

// alignedDetail pads a detail string to detailColumn so the duration column
// lines up across consecutive completion lines. Narrow terminals drop the
// padding instead of pushing content through the right edge.
func alignedDetail(detail string, width int) string {
	if detail == "" || width < 70 {
		return detail
	}
	pad := detailColumn - len([]rune(detail))
	if pad < 2 {
		pad = 2
	}
	return detail + strings.Repeat(" ", pad)
}

// renderEvent converts one orchestrator event into the lines it produces.
// An empty slice means the event is not shown at this verbosity.
func (r *Renderer) renderEvent(ev orchestrator.Event) []string {
	switch e := ev.(type) {
	case orchestrator.WaveStartEvent:
		return nil // phases are rendered by the wave handler in Handle
	case orchestrator.ModuleStartEvent:
		if !r.showLifecycle {
			return nil
		}
		return []string{r.lifecycleLine(TagRun, e.Name, "", 0)}
	case orchestrator.ModuleDoneEvent:
		return r.renderModuleDone(e)
	case orchestrator.WarningEvent:
		// Warnings always surface (Quiet included).
		return []string{r.eventLine(TagWarn, singleLine(e.Message))}
	case orchestrator.DeadlockEvent:
		// Deadlocks always surface (Quiet included).
		return []string{r.eventLine(TagWarn, singleLine(e.Message))}
	case orchestrator.ModuleProgressEvent:
		// Progress updates feed the volatile line, not the log.
		return nil
	default:
		return nil
	}
}

func (r *Renderer) renderModuleDone(e orchestrator.ModuleDoneEvent) []string {
	switch {
	case e.Status == "skipped":
		if !r.showLifecycle {
			return nil
		}
		reason := "dependency unavailable"
		switch {
		case e.Reason != "":
			reason = singleLine(e.Reason)
		case e.Error != "":
			reason = singleLine(e.Error)
		}
		return []string{r.lifecycleLine(TagSkip, e.Name, r.th.Subtle(reason), e.Dur)}
	case e.Status == "aborted":
		if !r.showLifecycle {
			return nil
		}
		return []string{r.lifecycleLine(TagWarn, e.Name, r.th.Orange("aborted"), e.Dur)}
	case e.Failed:
		// Module failures must never disappear below Normal verbosity, but
		// a dry run (where nothing actually executed) keeps its output
		// clean unless -v asks for the full lifecycle.
		if !r.showLifecycle && r.verbosity >= Normal {
			return nil
		}
		if e.Error != "" && r.showLifecycle {
			return r.errorBlock(e)
		}
		detail := singleLine(e.Status)
		if strings.TrimSpace(e.Status) == "failed" && e.Error != "" {
			// A bare "failed" status is redundant with the [ERR] tag; the
			// first line of the real error is worth the space instead.
			detail = singleLine(firstLine(e.Error))
		}
		return []string{r.lifecycleLine(TagError, e.Name, detail, e.Dur)}
	default:
		if !r.showLifecycle {
			return nil
		}
		detail := alignedDetail(singleLine(e.Summary), r.term.Width)
		return []string{r.lifecycleLine(TagOK, e.Name, detail, e.Dur)}
	}
}

// errorBlock renders an actionable module failure: what failed, why, whether
// the scan continues and what the operator can do next.
func (r *Renderer) errorBlock(e orchestrator.ModuleDoneEvent) []string {
	head := r.eventLine(TagError, r.th.Bold(e.Name))
	indent := strings.Repeat(" ", tagIndent)
	message := singleLine(e.Error)
	row := func(label, value string) string {
		return indent + r.th.Dim(fmt.Sprintf("%-10s", label)) + "  " + value
	}

	action, hint := failureAdvice(e.Name, e.Kind, r.profile)

	lines := []string{head, ""}
	lines = append(lines, indent+r.th.Subtle(message))
	lines = append(lines, "")
	lines = append(lines, row("action", action))
	if hint != "" {
		lines = append(lines, row("hint", hint))
	}
	if d := formatDuration(e.Dur); d != "" {
		lines = append(lines, row("took", r.th.Dim(d)))
	}
	lines = append(lines, "")
	return lines
}

// failureAdvice tailors the action/hint shown for a module failure to why
// it actually failed, instead of the same generic "run scanforge doctor"
// regardless of cause. hint is "" when there is nothing useful to suggest
// (e.g. the operator cancelled the scan themselves).
func failureAdvice(moduleName string, kind runner.FailureKind, profile string) (action, hint string) {
	switch kind {
	case runner.FailureNotFound:
		return "scan continues", fmt.Sprintf(
			"%s is missing or not executable; run `scanforge doctor --profile %s` to confirm, then install it", moduleName, profile)
	case runner.FailureTimeout:
		if moduleName == "nuclei" {
			// The only module with a dedicated CLI timeout flag today; every
			// other module's Command.Timeout is an internal constant, so
			// naming a flag that doesn't exist would be a worse hint than
			// none at all.
			return "scan continues", "raise --nuclei-timeout for slow proxies or large target lists"
		}
		return "scan continues", "the target or wordlist is larger/slower than this module's time budget; narrow the scope or profile and re-run"
	case runner.FailureCanceled:
		return "scan aborted", ""
	default:
		return "scan continues", "run `scanforge doctor --profile " + profile + "`"
	}
}

// tagIndent is the column where the message starts on a tagged line:
// "[HH:MM:SS] [TAG] " → 12 + 6 = 18. Continuation lines of multi-line
// blocks align with it.
const tagIndent = 18

// singleLine strips control characters (tool output can contain \r or ANSI)
// and pre-rendered color so the console is always the single styling layer.
func singleLine(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, ansi.Strip(s))
}

// firstLine returns everything before the first newline of a multi-line
// message, so compact lines stay compact.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
