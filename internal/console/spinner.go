package console

import (
	"os"
	"strings"
	"time"
)

// SpinnerStyle selects the animation drawn at the start of the volatile
// progress line. The line only exists on interactive terminals, so these
// styles never reach pipes, CI logs or report files.
type SpinnerStyle int

const (
	// SpinnerForge uses the generated hammer/anvil sprite; narrow terminals use dots.
	SpinnerForge SpinnerStyle = iota
	// SpinnerDots is the calm, classic quarter-circle spinner.
	SpinnerDots
	// SpinnerOff hides the animation entirely.
	SpinnerOff
)

// SpinnerChomp remains a source-compatible alias; the old animation is gone.
const SpinnerChomp = SpinnerForge

// dotFrames is the classic quarter-circle rotation.
var dotFrames = []string{"◐", "◓", "◑", "◒"}

// spinnerInterval is one animation tick. The volatile line redraws on the
// same cadence, so frames advance smoothly without extra timers.
const spinnerInterval = 120 * time.Millisecond

// frame returns the single-row fallback prefix, including its separating space.
// The generated forge sprite is rendered separately alongside the status.
func (s SpinnerStyle) frame(now time.Time) string {
	tick := int(now.UnixNano() / int64(spinnerInterval))
	switch s {
	case SpinnerOff:
		return ""
	case SpinnerDots:
		return dotFrames[tick%len(dotFrames)] + " "
	default:
		return dotFrames[tick%len(dotFrames)] + " "
	}
}

// styledFrame colors the compact pixel icon in ember amber.
func (s SpinnerStyle) styledFrame(now time.Time, th theme) string {
	frame := s.frame(now)
	if frame == "" || !th.enabled {
		return frame
	}
	return th.Accent(strings.TrimSuffix(frame, " ")) + " "
}

// ResolveSpinner resolves SCANFORGE_SPINNER:
// "off"/"none"/"0"/"false" hides the animation, "dots"/"classic" selects the
// quarter-circle spinner, and an unset (or unknown) value keeps the default
// forge. Legacy names also select the forge animation.
func ResolveSpinner() SpinnerStyle {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SCANFORGE_SPINNER"))) {
	case "off", "none", "0", "false", "no":
		return SpinnerOff
	case "dots", "classic", "spinner", "braille":
		return SpinnerDots
	case "forge", "smith", "anvil", "chomp", "muncher", "pacman", "fun", "default":
		return SpinnerForge
	default:
		return SpinnerForge
	}
}
