// Package ui centralizes ScanForge's terminal styling (colors, tagged log
// lines, headers, panels, tables, progress bars, gradients) on top of
// lipgloss so every command shares one look instead of ad hoc formatting per
// call site.
package ui

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"golang.org/x/term"
)

// ScanForge palette — inspired by ProjectDiscovery's tools (nuclei, httpx:
// mostly neutral text with a cyan "[INF]" tag and severity-only color) for
// one-shot command output, and lazygit/k9s (bordered, purposeful panes, one
// accent for focus) for the live TUI. Color is reserved for meaning: cyan is
// the one brand/focus accent, not a wash applied to everything. Every color
// carries an ANSI 256 fallback so output stays readable without truecolor.
var (
	colorBorder = color("#1f2937", "236") // neutral slate — inactive frames, dividers
	colorDim    = color("#6b7280", "243") // secondary/meta text (durations, paths)
	colorSubtle = color("#9ca3af", "248") // slightly lighter than dim — descriptions
	colorText   = color("#e5e7eb", "254") // primary body text — off-white, not accent-colored
	colorAccent = color("#38bdf8", "38")  // brand / focus / "[INF]": the one recurring accent
	colorGreen  = color("#4ade80", "78")  // success
	colorYellow = color("#facc15", "220") // warning
	colorOrange = color("#fb923c", "215") // medium severity / user-initiated abort
	colorRed    = color("#f87171", "203") // error / critical / high severity
)

// Exported brand colors for composing panels, headers and banners.
var (
	Accent       = colorAccent
	AccentGreen  = colorGreen
	AccentYellow = colorYellow
	AccentOrange = colorOrange
	AccentRed    = colorRed
	BorderColor  = colorBorder
	Dimmed       = colorDim // for custom lipgloss styles built outside this package
)

// trueColor reports whether the terminal advertises 24-bit color support.
func supportsTrueColor() bool {
	ct := strings.ToLower(os.Getenv("COLORTERM"))
	if strings.Contains(ct, "truecolor") || strings.Contains(ct, "24bit") {
		return true
	}
	termEnv := strings.ToLower(os.Getenv("TERM"))
	for _, marker := range []string{"truecolor", "kitty", "wezterm", "alacritty", "ghostty", "foot"} {
		if strings.Contains(termEnv, marker) {
			return true
		}
	}
	return false
}

var trueColor = supportsTrueColor()

// color returns the truecolor hex when supported, otherwise the ANSI
// fallback code.
func color(hex, ansi string) lipgloss.Color {
	if trueColor {
		return lipgloss.Color(hex)
	}
	return lipgloss.Color(ansi)
}

// ---------------------------------------------------------------------------
// Plain color helpers
// ---------------------------------------------------------------------------

func Primary(s string) string   { return lipgloss.NewStyle().Foreground(colorAccent).Render(s) }
func Secondary(s string) string { return lipgloss.NewStyle().Foreground(colorSubtle).Render(s) }
func Text(s string) string      { return lipgloss.NewStyle().Foreground(colorText).Render(s) }
func Green(s string) string     { return lipgloss.NewStyle().Foreground(colorGreen).Render(s) }
func Yellow(s string) string    { return lipgloss.NewStyle().Foreground(colorYellow).Render(s) }
func Red(s string) string       { return lipgloss.NewStyle().Foreground(colorRed).Render(s) }
func Orange(s string) string    { return lipgloss.NewStyle().Foreground(colorOrange).Render(s) }
func Gray(s string) string      { return Dim(s) }
func Dim(s string) string       { return lipgloss.NewStyle().Foreground(colorDim).Render(s) }
func Bold(s string) string      { return lipgloss.NewStyle().Bold(true).Render(s) }
func DimBold(s string) string   { return lipgloss.NewStyle().Bold(true).Foreground(colorDim).Render(s) }

// Severity colors a finding severity label: critical/high → red, medium →
// orange, low → subtle, info → dim. Mirrors nuclei's own severity colors so
// the convention is already familiar to anyone who has used these tools.
func Severity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return lipgloss.NewStyle().Bold(true).Foreground(colorRed).Render(severity)
	case "high":
		return Red(severity)
	case "medium":
		return Orange(severity)
	case "low":
		return Secondary(severity)
	case "info":
		return Dim(severity)
	default:
		return severity
	}
}

// ---------------------------------------------------------------------------
// Log tags — minimal bracket tags like nuclei/httpx ("[INF]", "[WRN]"), not
// filled badges. The bracket itself stays dim; only the label is colored, so
// a stream of log lines reads calmly instead of as a row of colored blocks.
// ---------------------------------------------------------------------------

func printTag(labelColor lipgloss.Color, label, format string, args ...any) {
	bracket := lipgloss.NewStyle().Foreground(colorDim)
	tag := bracket.Render("[") + lipgloss.NewStyle().Bold(true).Foreground(labelColor).Render(label) + bracket.Render("]")
	_, _ = fmt.Fprintf(os.Stdout, "%s %s\n", tag, fmt.Sprintf(format, args...))
}

// Info prints a minimal "[INF]" tag followed by a message.
func Info(format string, args ...any)    { printTag(colorAccent, "INF", format, args...) }
func Success(format string, args ...any) { printTag(colorGreen, "OK", format, args...) }
func Warn(format string, args ...any)    { printTag(colorYellow, "WRN", format, args...) }
func Error(format string, args ...any)   { printTag(colorRed, "ERR", format, args...) }

// SuccessTag renders a standalone green glyph+label (no message, no newline).
func SuccessTag(label string) string { return Green(label) }

// ErrorTag renders a standalone red glyph+label (no message, no newline).
func ErrorTag(label string) string { return Red(label) }

// WarnTag renders a standalone yellow glyph+label (no message, no newline).
func WarnTag(label string) string { return Yellow(label) }

// SkipTag renders a standalone dim glyph+label for modules that never ran
// because an upstream dependency failed (no message, no newline).
func SkipTag(label string) string { return Dim(label) }

// AbortTag renders a standalone orange glyph+label for modules stopped by a
// user-initiated abort (no message, no newline).
func AbortTag(label string) string { return Orange(label) }

// ---------------------------------------------------------------------------
// Gradient
// ---------------------------------------------------------------------------

// Gradient renders plain text with a smooth per-character color transition
// from `from` to `to`. It requires truecolor; otherwise the text falls back
// to the primary accent. The input must not contain pre-rendered ANSI
// sequences.
func Gradient(text string, from, to lipgloss.Color) string {
	if !trueColor {
		return Primary(text)
	}
	fromRGB, okFrom := parseHex(from)
	toRGB, okTo := parseHex(to)
	if !okFrom || !okTo {
		return Primary(text)
	}
	runes := []rune(text)
	var b strings.Builder
	for i, r := range runes {
		t := 0.0
		if len(runes) > 1 {
			t = float64(i) / float64(len(runes)-1)
		}
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(lerpHex(fromRGB, toRGB, t))).Render(string(r)))
	}
	return b.String()
}

func parseHex(c lipgloss.Color) ([3]int, bool) {
	s := string(c)
	if len(s) != 7 || s[0] != '#' {
		return [3]int{}, false
	}
	var rgb [3]int
	for i := 0; i < 3; i++ {
		v, err := strconv.ParseUint(s[1+2*i:3+2*i], 16, 8)
		if err != nil {
			return [3]int{}, false
		}
		rgb[i] = int(v)
	}
	return rgb, true
}

func lerpHex(from, to [3]int, t float64) string {
	var c [3]int
	for i := 0; i < 3; i++ {
		c[i] = int(float64(from[i]) + (float64(to[i])-float64(from[i]))*t + 0.5)
	}
	return fmt.Sprintf("#%02x%02x%02x", c[0], c[1], c[2])
}

// ---------------------------------------------------------------------------
// Layout primitives
// ---------------------------------------------------------------------------

// terminalWidth returns the current stdout width, falling back to 80 columns
// when stdout isn't a TTY (redirected output, CI logs, dry-run to a file).
func terminalWidth() int {
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		return w
	}
	return 80
}

// Justify pads `left` and `right` on a single line of exactly `width`
// columns, e.g. a status bar's title on the left and a timer on the right.
// If both sides don't fit, a single space separates them instead of
// truncating either one.
func Justify(left, right string, width int) string {
	lw := lipgloss.Width(left)
	rw := lipgloss.Width(right)
	gap := width - lw - rw
	if gap < 1 {
		gap = 1
	}
	return left + strings.Repeat(" ", gap) + right
}

// Section renders a flat, unboxed block for one-shot command output (doctor,
// plan, version, run start/summary): a bold title, a dim divider the width
// of the title, then the body. Deliberately has no border — boxing every
// single piece of output is the kind of decorative filler that makes a CLI
// feel templated rather than purpose-built; the box is reserved for the live
// TUI's panes, where it marks a real functional region.
func Section(title, body string) string {
	return SectionWith(title, body, colorAccent)
}

// SectionWith is Section with an explicit title color, for the rare case
// where the heading itself needs to carry a signal (e.g. the final run
// status: green/yellow/red instead of the default accent).
func SectionWith(title, body string, titleColor lipgloss.Color) string {
	var b strings.Builder
	if title != "" {
		rendered := lipgloss.NewStyle().Bold(true).Foreground(titleColor).Render(title)
		b.WriteString(rendered)
		b.WriteString("\n")
		b.WriteString(Dim(strings.Repeat("─", lipgloss.Width(rendered))))
		b.WriteString("\n")
	}
	b.WriteString(body)
	return b.String()
}

// PanelWith renders a rounded-border box with a colored title and a matching
// divider line. Reserved for the live TUI's functional panes (a real,
// distinct region of the screen) — one-shot command output should use
// Section instead so boxes don't become decorative wallpaper.
func PanelWith(title, body string, border, titleColor lipgloss.Color) string {
	var content strings.Builder
	if title != "" {
		titleStyle := lipgloss.NewStyle().Bold(true).Foreground(titleColor)
		renderedTitle := titleStyle.Render(title)
		content.WriteString(renderedTitle)
		content.WriteString("\n")
		content.WriteString(strings.Repeat("─", lipgloss.Width(renderedTitle)+2))
		content.WriteString("\n\n")
	}
	content.WriteString(body)
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(border).
		Padding(0, 1).
		Render(content.String())
}

// Panel renders a rounded-border box with an accent-colored title and a
// neutral frame.
func Panel(title, body string) string {
	return PanelWith(title, body, colorBorder, colorAccent)
}

// ProgressBar renders a block-based progress bar with a count, e.g.
// "█████░░░░░░░░░░░░░░░ 3/5". The bar turns green when complete.
func ProgressBar(completed, total, width int) string {
	if width <= 0 {
		width = 20
	}
	if total <= 0 {
		total = completed
	}
	if total <= 0 {
		// Nothing to count (failed or empty run): render an empty bar instead
		// of dividing by zero.
		return fmt.Sprintf("%s 0/0", strings.Repeat("░", width))
	}
	if completed > total {
		completed = total
	}
	filled := int(float64(completed) / float64(total) * float64(width))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	barStyle := lipgloss.NewStyle().Foreground(colorAccent)
	if completed == total {
		barStyle = lipgloss.NewStyle().Foreground(colorGreen)
	}
	return fmt.Sprintf("%s %d/%d", barStyle.Render(bar), completed, total)
}

// WaveHeader renders a full-width section header for an execution wave, e.g.
// "────── Wave 1 · subfinder, dnsx ──────".
func WaveHeader(wave int, modules string) string {
	label := fmt.Sprintf("Wave %d", wave)
	if modules != "" {
		label += " · " + modules
	}
	head := lipgloss.NewStyle().Bold(true).Foreground(colorAccent).Render(label)
	width := terminalWidth()
	fill := width - lipgloss.Width(head) - 4
	if fill < 2 {
		fill = 2
	}
	rule := lipgloss.NewStyle().Foreground(colorBorder).Render(strings.Repeat("─", fill))
	return rule + " " + head + " " + rule
}

// CommandLine renders a shell command dimmed with a colored prompt, as used
// by dry runs and the commands log.
func CommandLine(command string) string {
	prompt := lipgloss.NewStyle().Bold(true).Foreground(colorAccent).Render("$")
	return prompt + " " + lipgloss.NewStyle().Foreground(colorDim).Render(command)
}

// Table renders a bordered, header-having table, replacing
// pterm.DefaultTable.WithHasHeader().WithBoxed().
func Table(headers []string, rows [][]string) string {
	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(lipgloss.NewStyle().Foreground(colorBorder)).
		Headers(headers...).
		Rows(rows...).
		StyleFunc(func(row, _ int) lipgloss.Style {
			style := lipgloss.NewStyle().Padding(0, 1)
			if row == table.HeaderRow {
				return style.Bold(true).Foreground(colorDim)
			}
			return style.Foreground(colorText)
		})
	return t.Render()
}

// StatusSymbol returns a colored glyph for a doctor/plan-style check status:
// "ok", "warn", or "fail".
func StatusSymbol(status string) string {
	switch status {
	case "ok":
		return Green("✓")
	case "warn":
		return Yellow("!")
	case "fail":
		return Red("✗")
	default:
		return Dim(status)
	}
}

// ColorizeRisk colors a plan step's risk label (passive/active-low/active/active-high).
func ColorizeRisk(risk string) string {
	switch risk {
	case "passive":
		return Green(risk)
	case "active-low":
		return Secondary(risk)
	case "active":
		return Yellow(risk)
	case "active-high":
		return Red(risk)
	default:
		return Dim(risk)
	}
}
