// Package ascii renders the ScanForge wordmark shown at startup. The banner
// combines a pixel smith with a bitmap wordmark and adapts to terminal width.
package ascii

import (
	"os"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/version"
)

// Banner composes the pixel smith and bitmap lettering for the available width.
func Banner(width int) (art, tagline string, ok bool) {
	if width < 40 {
		return "", "", false
	}
	tagline = "v" + version.Version + " / reconnaissance framework"
	if len(tagline) > width {
		tagline = "ScanForge"
	}
	left := strings.Split(BannerSmith(false, false), "\n")
	if width >= 90 {
		right := append([]string{"", ""}, strings.Split(pixelWordmark(), "\n")...)
		for i := range left {
			if i < len(right) {
				left[i] += "    " + right[i]
			}
		}
		return strings.Join(left, "\n"), tagline, true
	}
	if width >= 46 {
		return BannerSmith(false, false) + "\n\n" + pixelWordmark(), tagline, true
	}
	return strings.TrimRight(BannerSmith(false, false), " ") + "\n  S C A N F O R G E", tagline, true
}

// BannerSetting selects how the wordmark is shown: automatic (TTY decides),
// forced on, or forced off.
type BannerSetting int

const (
	BannerAuto BannerSetting = iota
	BannerOn
	BannerOff
)

// ResolveBannerSetting resolves the SCANFORGE_BANNER environment variable:
// "off"/"none"/"0"/"false" disables the banner, any other value forces it
// on, and an unset variable leaves the decision to the caller (TTY-based).
func ResolveBannerSetting() BannerSetting {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SCANFORGE_BANNER"))) {
	case "off", "none", "0", "false", "no":
		return BannerOff
	case "":
		return BannerAuto
	default:
		return BannerOn
	}
}
