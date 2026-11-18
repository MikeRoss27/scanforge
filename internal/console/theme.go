// Package console renders ScanForge's live scan output as a chronological,
// tagged event log in the spirit of modern offensive-security CLIs
// (sqlmap, nuclei, Ghauri): the terminal keeps its scrollback, every line is
// copy/paste and grep friendly, and there is no fullscreen interface.
//
// The renderer is fed semantic events by the orchestrator and decides how
// they look; scanning logic never prints styled output itself.
package console

import (
	"fmt"
	"strings"
)

// color carries the truecolor SGR parameter and the ANSI 256 fallback for one
// palette entry, so output stays readable on terminals without 24-bit color.
type color struct{ tc, a256 string }

var (
	colAccent = color{"38;2;232;176;89", "38;5;179"}  // interaction, info, active state
	colGreen  = color{"38;2;74;222;128", "38;5;78"}   // success
	colYellow = color{"38;2;250;204;21", "38;5;220"}  // warning
	colOrange = color{"38;2;251;146;60", "38;5;215"}  // medium severity, aborted
	colRed    = color{"38;2;248;113;113", "38;5;203"} // high, critical, error
	colDim    = color{"38;2;107;114;128", "38;5;243"} // metadata, secondary text
	colSubtle = color{"38;2;156;163;175", "38;5;248"} // slightly lighter secondary
)

// theme holds the color switch for one renderer. When disabled, every
// helper returns its input unchanged, so no ANSI sequence can ever leak
// into piped, redirected or machine-readable output.
type theme struct {
	enabled   bool
	truecolor bool
}

// newTheme resolves color support from the environment. It never colors
// output unless explicitly told to, and honors NO_COLOR and TERM=dumb.
func newTheme(enabled bool) theme {
	return theme{enabled: enabled, truecolor: detectTrueColor()}
}

// paint wraps s in the SGR sequence for c. params may carry additional
// attributes (e.g. "1" for bold) joined with ";".
func (t theme) paint(c color, params string, s string) string {
	if !t.enabled || s == "" {
		return s
	}
	code := c.a256
	if t.truecolor {
		code = c.tc
	}
	if params != "" {
		code = params + ";" + code
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (t theme) Accent(s string) string { return t.paint(colAccent, "", s) }
func (t theme) Green(s string) string  { return t.paint(colGreen, "", s) }
func (t theme) Yellow(s string) string { return t.paint(colYellow, "", s) }
func (t theme) Orange(s string) string { return t.paint(colOrange, "", s) }
func (t theme) Red(s string) string    { return t.paint(colRed, "", s) }
func (t theme) Dim(s string) string    { return t.paint(colDim, "2", s) }
func (t theme) Subtle(s string) string { return t.paint(colSubtle, "", s) }
func (t theme) Bold(s string) string {
	if !t.enabled || s == "" {
		return s
	}
	return "\x1b[1m" + s + "\x1b[0m"
}

// DimBold renders secondary labels (summary keys, headers) — dim enough to
// stay out of the way, bold enough to structure the layout.
func (t theme) DimBold(s string) string {
	if !t.enabled || s == "" {
		return s
	}
	return "\x1b[1;2m" + s + "\x1b[0m"
}

// Severity colors a severity label the way operators expect to read it:
// critical/high jump out in red, medium lands in orange, low and info step
// back into neutral tones.
func (t theme) Severity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return t.paint(colRed, "1", severity)
	case "high":
		return t.Red(severity)
	case "medium":
		return t.Orange(severity)
	case "low":
		return t.Subtle(severity)
	case "info", "":
		return t.Dim(severity)
	default:
		return severity
	}
}

// Tag colors describe the event language: INF/RUN are interaction (amber),
// OK success, WRN warning, ERR error, SKP skipped (dim). FND is rendered
// through Severity so findings carry their severity color.
func tagColor(th theme, tag string) string {
	switch strings.TrimSpace(tag) {
	case "INF", "RUN":
		return th.Accent(tag)
	case "OK":
		return th.Green(tag)
	case "WRN":
		return th.Yellow(tag)
	case "ERR":
		return th.Red(tag)
	case "SKP":
		return th.Dim(tag)
	default:
		return tag
	}
}

// tag renders a fixed-width event tag, e.g. "[OK ]". The bracket stays dim
// and only the label is colored so a stream of log lines reads calmly.
func (t theme) tag(kind string) string {
	label := fmt.Sprintf("%-3s", kind)
	open := t.paint(colDim, "2", "[")
	close := t.paint(colDim, "2", "]")
	return open + tagColor(t, label) + close
}

// timestamp renders a dim [HH:MM:SS] stamp.
func (t theme) timestamp(stamp string) string {
	return t.paint(colDim, "2", "["+stamp+"]")
}

// rule renders "── LABEL ─────…", a phase/finding separator that fills the
// available width without ever exceeding it. The dash run is painted once,
// not per glyph, so rules stay compact in scrollback.
func (t theme) rule(label string, width int) string {
	if width < 10 {
		width = 10
	}
	if label == "" {
		return t.paint(colDim, "2", strings.Repeat("─", width))
	}
	head := t.paint(colDim, "2", "── ") + t.Bold(label) + " "
	used := 3 + len([]rune(label)) + 1
	if used >= width {
		return strings.TrimRight(head, " ")
	}
	return head + t.paint(colDim, "2", strings.Repeat("─", width-used))
}

// ---------------------------------------------------------------------------
// Event tags — the complete event language. Consistency matters more than
// decoration: no tool invents its own label set.
// ---------------------------------------------------------------------------

// Event tag kinds used across the console.
const (
	TagInfo  = "INF"
	TagRun   = "RUN"
	TagOK    = "OK"
	TagWarn  = "WRN"
	TagFound = "FND"
	TagError = "ERR"
	TagSkip  = "SKP"
)
