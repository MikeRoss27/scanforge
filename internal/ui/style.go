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

// ScanForge Tactical palette — muted, high-contrast, pentest-grade.
// Inspired by Catppuccin Mocha / Tokyo Night / Gruvbox + ProjectDiscovery
// minimalism: one calm brand accent (blue) + semantic severity colors +
// neutral slate grays. Avoids the previous dracula neon violet/pink/cyan
// rainbow that hurt readability and looked toy-like. Every color carries an
// ANSI 0-15 fallback.
var (
	colorBg      = color("#0f111a", "235") // deep ink, for tag foregrounds only
	colorSurface = color("#1a1d29", "236") // panel surface (not directly used, lipgloss is transparent)
	colorBorder  = color("#2a2e3f", "238") // subtle slate border
	colorDim     = color("#7a8196", "8")   // muted slate - secondary text
	colorSubtle  = color("#8b92a8", "7")   // slightly lighter muted
	colorText    = color("#d9e1f2", "15")  // primary text on dark
	colorAccent  = color("#7aa2f7", "12")  // primary brand: calm tokyonight blue (not neon cyan)
	colorMagenta = color("#7aa2f7", "12")  // deprecated: mapped to accent to kill pink gradient
	colorPurple  = color("#5b7cc2", "4")   // deprecated: muted indigo, never pink
	colorGreen   = color("#3fb950", "10")  // success - github green, desaturated
	colorYellow  = color("#d29922", "11")  // warning - gruvbox amber, not neon
	colorOrange  = color("#f0883e", "3")   // abort - warm orange
	colorRed     = color("#f85149", "9")   // danger - muted github red
)

// Exported brand colors for composing panels, headers and banners.
var (
	Accent        = colorAccent
	AccentCyan    = colorAccent // kept for backwards compatibility
	AccentMagenta = colorAccent // mapped to accent - no more pink
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
// Plain color helpers — single source of truth for text styling.
// Secondary is now muted slate, not pink — use Primary for brand emphasis.
// ---------------------------------------------------------------------------

func Primary(s string) string   { return lipgloss.NewStyle().Foreground(colorAccent).Render(s) }
func Secondary(s string) string { return lipgloss.NewStyle().Foreground(colorSubtle).Render(s) }
func Muted(s string) string     { return lipgloss.NewStyle().Foreground(colorDim).Render(s) }
func Subtle(s string) string    { return lipgloss.NewStyle().Foreground(colorSubtle).Render(s) }
func Faint(s string) string     { return lipgloss.NewStyle().Foreground(colorDim).Faint(true).Render(s) }
func Green(s string) string     { return lipgloss.NewStyle().Foreground(colorGreen).Render(s) }
func Yellow(s string) string    { return lipgloss.NewStyle().Foreground(colorYellow).Render(s) }
func Red(s string) string       { return lipgloss.NewStyle().Foreground(colorRed).Render(s) }
func Cyan(s string) string      { return Primary(s) }
func Magenta(s string) string   { return Primary(s) } // pink removed: alias to primary
func Orange(s string) string    { return lipgloss.NewStyle().Foreground(colorOrange).Render(s) }
func Purple(s string) string    { return lipgloss.NewStyle().Foreground(colorPurple).Render(s) }
func Gray(s string) string      { return Dim(s) }
func Dim(s string) string       { return lipgloss.NewStyle().Foreground(colorDim).Render(s) }
func Bold(s string) string      { return lipgloss.NewStyle().Bold(true).Render(s) }
func DimBold(s string) string   { return lipgloss.NewStyle().Bold(true).Foreground(colorDim).Render(s) }

// AccentBold renders text in brand blue bold - for titles, targets.
func AccentBold(s string) string {
	return lipgloss.NewStyle().Bold(true).Foreground(colorAccent).Render(s)
}

// Severity colors a finding severity label: critical/high → red, medium →
// amber, low → blue, info → muted. Mirrors nuclei/httpx conventions where
// severity is the only saturated element on the line.
func Severity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return lipgloss.NewStyle().Bold(true).Foreground(colorRed).Render(severity)
	case "high":
		return lipgloss.NewStyle().Bold(true).Foreground(colorRed).Render(severity)
	case "medium":
		return lipgloss.NewStyle().Foreground(colorYellow).Render(severity)
	case "low":
		return lipgloss.NewStyle().Foreground(colorAccent).Render(severity)
	case "info":
		return lipgloss.NewStyle().Foreground(colorDim).Render(severity)
	default:
		return Dim(severity)
	}
}

// ---------------------------------------------------------------------------
// Log tags
// ---------------------------------------------------------------------------

var (
	// Minimal bracket tags like nuclei/httpx: "[INF]" " [WRN]" — no heavy pill
	// background. High contrast via bold foreground + subtle bracket dim.
	tagInfo    = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	tagSuccess = lipgloss.NewStyle().Bold(true).Foreground(colorGreen)
	tagWarn    = lipgloss.NewStyle().Bold(true).Foreground(colorYellow)
	tagError   = lipgloss.NewStyle().Bold(true).Foreground(colorRed)
	tagSkip    = lipgloss.NewStyle().Bold(true).Foreground(colorDim)
	tagAbort   = lipgloss.NewStyle().Bold(true).Foreground(colorOrange)
)

func printTag(style lipgloss.Style, label, format string, args ...any) {
	bracket := lipgloss.NewStyle().Foreground(colorDim).Render("[")
	bracketClose := lipgloss.NewStyle().Foreground(colorDim).Render("]")
	tag := bracket + style.Render(label) + bracketClose
	_, _ = fmt.Fprintf(os.Stdout, "%s %s\n", tag, fmt.Sprintf(format, args...))
}

// Info prints a minimal [INFO] tag followed by a message — aligns with
// ProjectDiscovery style (e.g. nuclei [INF], [WRN]) instead of pill badges.
func Info(format string, args ...any)    { printTag(tagInfo, "INF", format, args...) }
func Success(format string, args ...any) { printTag(tagSuccess, "OK", format, args...) }
func Warn(format string, args ...any)    { printTag(tagWarn, "WRN", format, args...) }
func Error(format string, args ...any)   { printTag(tagError, "ERR", format, args...) }

var (
	// Subtle pill badges for TUI table — background is border color, foreground
	// is semantic. Much calmer than previous neon pill with Bg=accent.
	badgeSuccess = lipgloss.NewStyle().Bold(true).Foreground(colorGreen).Background(colorBorder).Padding(0, 1)
	badgeError   = lipgloss.NewStyle().Bold(true).Foreground(colorRed).Background(colorBorder).Padding(0, 1)
	badgeWarn    = lipgloss.NewStyle().Bold(true).Foreground(colorYellow).Background(colorBorder).Padding(0, 1)
	badgeSkip    = lipgloss.NewStyle().Bold(true).Foreground(colorDim).Background(colorBorder).Padding(0, 1)
	badgeAbort   = lipgloss.NewStyle().Bold(true).Foreground(colorOrange).Background(colorBorder).Padding(0, 1)
)

// SuccessTag renders a standalone green badge (no message, no newline).
func SuccessTag(label string) string { return badgeSuccess.Render(label) }

// ErrorTag renders a standalone red badge (no message, no newline).
func ErrorTag(label string) string { return badgeError.Render(label) }

// WarnTag renders a standalone yellow badge (no message, no newline).
func WarnTag(label string) string { return badgeWarn.Render(label) }

// SkipTag renders a standalone dim badge for modules that never ran because
// an upstream dependency failed (no message, no newline).
func SkipTag(label string) string { return badgeSkip.Render(label) }

// AbortTag renders a standalone orange badge for modules stopped by a
// user-initiated abort (no message, no newline).
func AbortTag(label string) string { return badgeAbort.Render(label) }

// ---------------------------------------------------------------------------
// Gradient
// ---------------------------------------------------------------------------

// Gradient is kept for API compatibility but now renders as a single calm
// brand color (no rainbow). The previous cyan→magenta per-character blend
// was the main source of the "violet, rose, bleu bizarre" complaint and is
// inconsistent with top pentest tools (nuclei, httpx, naabu) which all use
// single-color banners. Callers should prefer Primary/Bold directly.
func Gradient(text string, _, _ lipgloss.Color) string {
	return lipgloss.NewStyle().Bold(true).Foreground(colorAccent).Render(text)
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

// Header renders a centered, bordered pill — no longer a heavy full-width
// background bar. The bg param is treated as foreground/border accent so
// "Initialization Complete" in green still reads as success without flooding
// the terminal. Much closer to glamour/gum minimal panels.
func Header(text string, bg lipgloss.Color) string {
	return lipgloss.NewStyle().
		Bold(true).
		Foreground(bg).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(bg).
		Padding(0, 2).
		Align(lipgloss.Center).
		Render(text)
}

// PanelWith renders a rounded-border box with a muted divider. The border
// is always subtle slate; titleColor tints only the title text. This avoids
// the previous "all panels cyan" monotony and lets semantic borders (green/
// yellow/red for summary) stand out while normal panels stay calm.
func PanelWith(title, body string, border, titleColor lipgloss.Color) string {
	var content strings.Builder
	if title != "" {
		// Title in accent, small tracking, icon already in caller.
		titleStyle := lipgloss.NewStyle().Bold(true).Foreground(titleColor)
		renderedTitle := titleStyle.Render(title)
		content.WriteString(renderedTitle)
		content.WriteString("\n")
		// Divider in muted border, not title color — less noisy.
		content.WriteString(lipgloss.NewStyle().Foreground(colorBorder).Render(strings.Repeat("─", lipgloss.Width(renderedTitle)+2)))
		content.WriteString("\n\n")
	}
	content.WriteString(body)
	// Border is caller's semantic color only if it's green/yellow/red, else subtle.
	borderStyle := colorBorder
	if border == colorGreen || border == colorYellow || border == colorRed || border == colorOrange {
		borderStyle = border
	}
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(borderStyle).
		Padding(0, 1).
		Render(content.String())
}

// Panel renders a rounded-border box with a subtle frame and accent title.
func Panel(title, body string) string {
	return PanelWith(title, body, colorBorder, colorAccent)
}

// ProgressBar renders a subtle track with accent fill: "▓▓▓░░░ 3/5".
// Empty track uses dim border color, fill accent, completed uses success green.
// Thin enough to not dominate the TUI footer (vs previous heavy cyan).
func ProgressBar(completed, total, width int) string {
	if width <= 0 {
		width = 20
	}
	if total <= 0 {
		total = completed
	}
	if total <= 0 {
		return Dim(strings.Repeat("░", width)) + Dim(" 0/0")
	}
	if completed > total {
		completed = total
	}
	filled := int(float64(completed) / float64(total) * float64(width))
	filledBar := strings.Repeat("━", filled)
	emptyBar := strings.Repeat("─", width-filled)
	var bar string
	if completed == total && total > 0 {
		bar = lipgloss.NewStyle().Foreground(colorGreen).Render(filledBar) + lipgloss.NewStyle().Foreground(colorBorder).Render(emptyBar)
	} else {
		bar = lipgloss.NewStyle().Foreground(colorAccent).Render(filledBar) + lipgloss.NewStyle().Foreground(colorBorder).Render(emptyBar)
	}
	count := Dim(fmt.Sprintf("%d/%d", completed, total))
	return bar + " " + count
}

// WaveHeader renders a calm wave divider: "─ Wave 1 · subfinder, dnsx ─".
// Uses dim rules and accent label, not heavy full-width bars.
func WaveHeader(wave int, modules string) string {
	label := fmt.Sprintf("Wave %d", wave)
	if modules != "" {
		// modules in muted, wave in accent
		label = lipgloss.NewStyle().Bold(true).Foreground(colorAccent).Render(fmt.Sprintf("Wave %d", wave)) +
			Dim(" · "+modules)
	} else {
		label = lipgloss.NewStyle().Bold(true).Foreground(colorAccent).Render(label)
	}
	width := terminalWidth()
	fill := (width - lipgloss.Width(label) - 4) / 2
	if fill < 2 {
		fill = 2
	}
	rule := lipgloss.NewStyle().Foreground(colorBorder).Render(strings.Repeat("─", fill))
	return Dim(rule+" ") + label + Dim(" "+rule)
}

// CommandLine renders a shell command dimmed with a muted prompt.
func CommandLine(command string) string {
	prompt := lipgloss.NewStyle().Foreground(colorDim).Render("›")
	return prompt + " " + lipgloss.NewStyle().Foreground(colorSubtle).Render(command)
}

// Table renders a bordered table with muted header and subtle grid — matches
// nuclei/httpx minimal tables where header is dim, not saturated. Keeps data
// readable when many modules are listed.
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
		return Cyan(risk)
	case "active":
		return Yellow(risk)
	case "active-high":
		return Red(risk)
	default:
		return Dim(risk)
	}
}
