package console

import (
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"
)

// DefaultWidth is the layout width used when the real terminal width is
// unknown (redirected output, CI). It matches the classic 80-column baseline
// the reference layouts were designed against.
const DefaultWidth = 80

// Terminal describes the output destination: whether it is an interactive
// terminal (colors, volatile progress line) and how wide it is.
type Terminal struct {
	// Tty is true when the writer is an interactive terminal.
	Tty bool
	// Volatile is true when carriage-return progress lines are safe: a real
	// TTY that is not TERM=dumb and not a CI runner.
	Volatile bool
	// Width is the terminal width in columns.
	Width int
}

// DetectTerminal inspects the environment for the writer. Width comes from
// COLUMNS when set, then the terminal itself, then DefaultWidth.
func DetectTerminal(w io.Writer) Terminal {
	t := Terminal{Width: DefaultWidth}

	f, isFile := w.(*os.File)
	if isFile && isTTY(f) {
		t.Tty = true
		if cols, _, err := term.GetSize(int(f.Fd())); err == nil && cols > 0 {
			t.Width = cols
		}
	}
	if cols := columnsFromEnv(); cols > 0 {
		t.Width = cols
	}
	t.Volatile = t.Tty && !dumbTerminal() && !runningInCI()
	if t.Width < 20 {
		t.Width = 20
	}
	return t
}

func isTTY(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

func columnsFromEnv() int {
	value := strings.TrimSpace(os.Getenv("COLUMNS"))
	if value == "" {
		return 0
	}
	cols, err := strconv.Atoi(value)
	if err != nil || cols <= 0 {
		return 0
	}
	return cols
}

func dumbTerminal() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("TERM")), "dumb")
}

func runningInCI() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("CI"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// ColorEnabled decides whether ANSI colors may be emitted for the writer.
// Auto behavior colors only interactive terminals; NO_COLOR (and TERM=dumb)
// disable it, and CLICOLOR_FORCE / FORCE_COLOR / SCANFORGE_COLOR=always can
// force colors for tools like tee and less -R.
func ColorEnabled(w io.Writer) bool {
	if forced, ok := forcedColor(); ok {
		return forced
	}
	if _, set := os.LookupEnv("NO_COLOR"); set {
		return false
	}
	if dumbTerminal() {
		return false
	}
	f, isFile := w.(*os.File)
	return isFile && isTTY(f)
}

// forcedColor resolves the explicit color override. Recognized values for
// SCANFORGE_COLOR, CLICOLOR_FORCE and FORCE_COLOR: always/1/true/on/yes →
// force on; never/0/false/off/no → force off; auto/empty → not set.
func forcedColor() (bool, bool) {
	names := []string{"SCANFORGE_COLOR", "CLICOLOR_FORCE", "FORCE_COLOR"}
	for _, name := range names {
		value, set := os.LookupEnv(name)
		if !set {
			continue
		}
		value = strings.ToLower(strings.TrimSpace(value))
		switch value {
		case "", "auto":
			continue
		case "always", "1", "true", "on", "yes":
			return true, true
		case "never", "0", "false", "off", "no":
			return false, true
		}
	}
	return false, false
}

func detectTrueColor() bool {
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
