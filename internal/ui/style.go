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

// ScanForge Dark palette — a dracula-inspired truecolor scheme. Every color
// carries an ANSI 0-15 fallback so output stays readable on terminals without
// truecolor support instead of degrading into mangled escape sequences.
var (
	colorBg      = color("#1e1f29", "235")
	colorBorder  = color("#3d3f4d", "238")
	colorDim     = color("#6272a4", "8")
	colorAccent  = color("#8be9fd", "14") // primary brand: cyan
	colorMagenta = color("#ff79c6", "13") // secondary brand
	colorPurple  = color("#bd93f9", "12")
	colorGreen   = color("#50fa7b", "10")
	colorYellow  = color("#f1fa8c", "11")
	colorOrange  = color("#ffb86c", "3")
	colorRed     = color("#ff5555", "9")
)

// Exported brand colors for composing panels, headers and banners.
var (
	Accent        = colorAccent
	AccentCyan    = colorAccent // kept for backwards compatibility
	AccentMagenta = colorMagenta
	AccentGreen   = colorGreen
	AccentYellow  = colorYellow
	AccentOrange  = colorOrange
	AccentRed     = colorRed
	BorderColor   = colorBorder
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
func Secondary(s string) string { return lipgloss.NewStyle().Foreground(colorMagenta).Render(s) }
func Green(s string) string     { return lipgloss.NewStyle().Foreground(colorGreen).Render(s) }
func Yellow(s string) string    { return lipgloss.NewStyle().Foreground(colorYellow).Render(s) }
func Red(s string) string       { return lipgloss.NewStyle().Foreground(colorRed).Render(s) }
func Cyan(s string) string      { return Primary(s) }
func Magenta(s string) string   { return Secondary(s) }
func Orange(s string) string    { return lipgloss.NewStyle().Foreground(colorOrange).Render(s) }
func Purple(s string) string    { return lipgloss.NewStyle().Foreground(colorPurple).Render(s) }
func Gray(s string) string      { return Dim(s) }
func Dim(s string) string       { return lipgloss.NewStyle().Foreground(colorDim).Render(s) }
func Bold(s string) string      { return lipgloss.NewStyle().Bold(true).Render(s) }
func DimBold(s string) string   { return lipgloss.NewStyle().Bold(true).Foreground(colorDim).Render(s) }

// Severity colors a finding severity label: critical/high → red, medium →
// yellow, low → cyan, info → dim, anything else → plain.
func Severity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return lipgloss.NewStyle().Bold(true).Foreground(colorRed).Render(severity)
	case "high":
		return Red(severity)
	case "medium":
		return Yellow(severity)
	case "low":
		return Cyan(severity)
	case "info":
		return Dim(severity)
	default:
		return severity
	}
}

// ---------------------------------------------------------------------------
// Log tags
// ---------------------------------------------------------------------------

var (
	tagInfo    = lipgloss.NewStyle().Bold(true).Foreground(colorBg).Background(colorAccent).Padding(0, 1)
	tagSuccess = lipgloss.NewStyle().Bold(true).Foreground(colorBg).Background(colorGreen).Padding(0, 1)
	tagWarn    = lipgloss.NewStyle().Bold(true).Foreground(colorBg).Background(colorYellow).Padding(0, 1)
	tagError   = lipgloss.NewStyle().Bold(true).Foreground(colorBg).Background(colorRed).Padding(0, 1)
)

func printTag(style lipgloss.Style, label, format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stdout, "%s %s\n", style.Render(label), fmt.Sprintf(format, args...))
}

// Info prints a colored INFO tag followed by a message.
func Info(format string, args ...any)    { printTag(tagInfo, "INFO", format, args...) }
func Success(format string, args ...any) { printTag(tagSuccess, "SUCCESS", format, args...) }
func Warn(format string, args ...any)    { printTag(tagWarn, "WARNING", format, args...) }
func Error(format string, args ...any)   { printTag(tagError, "ERROR", format, args...) }

// SuccessTag renders a standalone green badge (no message, no newline).
func SuccessTag(label string) string { return tagSuccess.Render(label) }

// ErrorTag renders a standalone red badge (no message, no newline).
func ErrorTag(label string) string { return tagError.Render(label) }

// WarnTag renders a standalone yellow badge (no message, no newline).
func WarnTag(label string) string { return tagWarn.Render(label) }

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

// Header renders a full-width colored bar with centered text, e.g. for the
// "ScanForge Run Started" / "Initialization Complete" banners. Width is
// measured from the real terminal instead of assumed.
func Header(text string, bg lipgloss.Color) string {
	return lipgloss.NewStyle().
		Bold(true).
		Foreground(colorBg).
		Background(bg).
		Width(terminalWidth()).
		Align(lipgloss.Center).
		Render(text)
}

// PanelWith renders a rounded-border box with a colored title and a matching
// divider line. `border` colors the frame, `titleColor` the title text.
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

// Panel renders a rounded-border box with an accent-colored title and frame.
func Panel(title, body string) string {
	return PanelWith(title, body, colorBorder, colorAccent)
}

// ProgressBar renders a block-based progress bar with a count, e.g.
// "█████░░░░░░░░░░░░░░░ 3/5". The bar turns green when complete.
func ProgressBar(completed, total, width int) string {
	if total <= 0 {
		total = completed
	}
	if completed > total {
		completed = total
	}
	if width <= 0 {
		width = 20
	}
	filled := int(float64(completed) / float64(total) * float64(width))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	barStyle := lipgloss.NewStyle().Foreground(colorAccent)
	if completed == total {
		barStyle = lipgloss.NewStyle().Foreground(colorGreen)
	}
	return fmt.Sprintf("%s %d/%d", barStyle.Render(bar), completed, total)
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
				return style.Bold(true).Foreground(colorAccent)
			}
			return style
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
		return Cyan(risk)
	case "active":
		return Yellow(risk)
	case "active-high":
		return Red(risk)
	default:
		return Dim(risk)
	}
}
