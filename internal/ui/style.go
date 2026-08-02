// Package ui centralizes ScanForge's terminal styling (colors, tagged log
// lines, headers, boxes, tables) on top of lipgloss so every command shares
// one look instead of ad hoc formatting per call site.
package ui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"golang.org/x/term"
)

// Palette. ANSI codes 0-15 keep terminal theming intact instead of forcing
// truecolor, matching how the rest of the CLI behaved under pterm.
var (
	colorFg      = lipgloss.Color("0")
	colorFgAlt   = lipgloss.Color("15")
	colorInfoBg  = lipgloss.Color("6")
	colorOKBg    = lipgloss.Color("10")
	colorWarnBg  = lipgloss.Color("11")
	colorErrBg   = lipgloss.Color("9")
	colorGreen   = lipgloss.Color("10")
	colorYellow  = lipgloss.Color("11")
	colorRed     = lipgloss.Color("9")
	colorCyan    = lipgloss.Color("14")
	colorMagenta = lipgloss.Color("13")
	colorGray    = lipgloss.Color("8")

	// AccentCyan and AccentGreen are the two header background colors used
	// across the CLI (run-started vs. init-complete banners).
	AccentCyan  = colorInfoBg
	AccentGreen = colorOKBg

	tagInfo    = lipgloss.NewStyle().Bold(true).Foreground(colorFg).Background(colorInfoBg).Padding(0, 1)
	tagSuccess = lipgloss.NewStyle().Bold(true).Foreground(colorFg).Background(colorOKBg).Padding(0, 1)
	tagWarn    = lipgloss.NewStyle().Bold(true).Foreground(colorFg).Background(colorWarnBg).Padding(0, 1)
	tagError   = lipgloss.NewStyle().Bold(true).Foreground(colorFgAlt).Background(colorErrBg).Padding(0, 1)
)

func printTag(style lipgloss.Style, label, format string, args ...any) {
	fmt.Fprintf(os.Stdout, "%s %s\n", style.Render(label), fmt.Sprintf(format, args...))
}

// Info, Success, Warn and Error print a colored tag followed by a message,
// mirroring the pterm.Info/Success/Warning/Error printers they replace.
func Info(format string, args ...any)    { printTag(tagInfo, "INFO", format, args...) }
func Success(format string, args ...any) { printTag(tagSuccess, "SUCCESS", format, args...) }
func Warn(format string, args ...any)    { printTag(tagWarn, "WARNING", format, args...) }
func Error(format string, args ...any)   { printTag(tagError, "ERROR", format, args...) }

// SuccessTag, ErrorTag and WarnTag render a standalone colored badge (no
// trailing message, no newline) for composing custom lines, e.g. the live
// per-module progress rows in the orchestrator.
func SuccessTag(label string) string { return tagSuccess.Render(label) }
func ErrorTag(label string) string   { return tagError.Render(label) }
func WarnTag(label string) string    { return tagWarn.Render(label) }

// Plain color helpers for composing custom lines (status text, severity
// counts, risk labels) without a leading tag.
func Green(s string) string   { return lipgloss.NewStyle().Foreground(colorGreen).Render(s) }
func Yellow(s string) string  { return lipgloss.NewStyle().Foreground(colorYellow).Render(s) }
func Red(s string) string     { return lipgloss.NewStyle().Foreground(colorRed).Render(s) }
func Cyan(s string) string    { return lipgloss.NewStyle().Foreground(colorCyan).Render(s) }
func Magenta(s string) string { return lipgloss.NewStyle().Foreground(colorMagenta).Render(s) }
func Gray(s string) string    { return lipgloss.NewStyle().Foreground(colorGray).Render(s) }
func Bold(s string) string    { return lipgloss.NewStyle().Bold(true).Render(s) }

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
// measured from the real terminal instead of assumed, which is what made
// pterm.DefaultHeader.WithFullWidth() render as an oversized, off-center box.
func Header(text string, bg lipgloss.Color) string {
	return lipgloss.NewStyle().
		Bold(true).
		Foreground(colorFg).
		Background(bg).
		Width(terminalWidth()).
		Align(lipgloss.Center).
		Render(text)
}

// Box renders a titled, rounded-border box sized to its content, replacing
// pterm.DefaultBox.WithTitle(...).
func Box(title, body string) string {
	content := body
	if title != "" {
		titleLine := lipgloss.NewStyle().Bold(true).Foreground(colorMagenta).Render(title)
		content = titleLine + "\n" + strings.Repeat("─", lipgloss.Width(titleLine)) + "\n" + body
	}
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorGray).
		Padding(0, 1).
		Render(content)
}

// Table renders a bordered, header-having table, replacing
// pterm.DefaultTable.WithHasHeader().WithBoxed().
func Table(headers []string, rows [][]string) string {
	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(lipgloss.NewStyle().Foreground(colorGray)).
		Headers(headers...).
		Rows(rows...).
		StyleFunc(func(row, _ int) lipgloss.Style {
			style := lipgloss.NewStyle().Padding(0, 1)
			if row == table.HeaderRow {
				return style.Bold(true)
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
		return Gray(status)
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
		return Gray(risk)
	}
}
