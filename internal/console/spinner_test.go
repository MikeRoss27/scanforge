package console

import (
	"strings"
	"testing"
	"time"

	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	"github.com/charmbracelet/x/ansi"
)

func TestForgeSpinnerKeepsFixedWidth(t *testing.T) {
	now := time.Unix(0, 0)
	first := SpinnerForge.frame(now)
	for i := 0; i < len(dotFrames)*2; i++ {
		frame := SpinnerForge.frame(now.Add(time.Duration(i) * spinnerInterval))
		if got := ansi.StringWidth(frame); got != 2 {
			t.Fatalf("frame %q width = %d, want 2 (fixed width keeps names aligned)", frame, got)
		}
		if !strings.ContainsAny(frame, "◐◓◑◒") {
			t.Errorf("forge frame lost the smith: %q", frame)
		}
	}
	if SpinnerForge.frame(now.Add(2*spinnerInterval)) == first {
		t.Errorf("forge animation did not advance after one interval: %q", first)
	}
}

func TestDotsSpinnerRotates(t *testing.T) {
	now := fixedClock()
	seen := map[string]bool{}
	for i := 0; i < len(dotFrames); i++ {
		frame := SpinnerDots.frame(now.Add(time.Duration(i) * spinnerInterval))
		if got := ansi.StringWidth(frame); got != 2 {
			t.Errorf("dots frame %q width = %d, want 2", frame, got)
		}
		for _, dot := range dotFrames {
			if frame == dot+" " {
				seen[dot] = true
			}
		}
	}
	if len(seen) != len(dotFrames) {
		t.Errorf("dots spinner repeated a frame: saw %v", seen)
	}
}

func TestSpinnerOffHasNoPrefix(t *testing.T) {
	if frame := SpinnerOff.frame(fixedClock()); frame != "" {
		t.Errorf("SpinnerOff prefix = %q, want empty", frame)
	}
}

func TestResolveSpinner(t *testing.T) {
	cases := map[string]SpinnerStyle{
		"":         SpinnerForge,
		"forge":    SpinnerForge,
		"pacman":   SpinnerForge,
		"smith":    SpinnerForge,
		"anvil":    SpinnerForge,
		"fun":      SpinnerForge,
		"dots":     SpinnerDots,
		"classic":  SpinnerDots,
		"braille":  SpinnerDots,
		"off":      SpinnerOff,
		"none":     SpinnerOff,
		"false":    SpinnerOff,
		"garbage":  SpinnerForge,
		"CHOMP":    SpinnerForge,
		"  dots  ": SpinnerDots,
	}
	for value, want := range cases {
		t.Setenv("SCANFORGE_SPINNER", value)
		if got := ResolveSpinner(); got != want {
			t.Errorf("ResolveSpinner(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestProgressViewUsesConfiguredSpinner(t *testing.T) {
	now := fixedClock()
	forge := newProgressTracker(SpinnerForge)
	forge.start("nuclei", now)
	if view := forge.view(now, 80, newTheme(false)); !strings.Contains(view, "nuclei") {
		t.Errorf("forge tracker view lacks the smith: %q", view)
	}

	dots := newProgressTracker(SpinnerDots)
	dots.start("nuclei", now)
	view := dots.view(now, 80, newTheme(false))
	found := false
	for _, dot := range dotFrames {
		if strings.HasPrefix(view, dot+" ") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("dots tracker view lacks a spinner frame: %q", view)
	}

	plain := newProgressTracker(SpinnerOff)
	plain.start("nuclei", now)
	if view := plain.view(now, 80, newTheme(false)); !strings.HasPrefix(view, "nuclei") {
		t.Errorf("spinner-off view should start with the module name: %q", view)
	}
}

func TestProgressViewCarriesRealCountsWithSpinner(t *testing.T) {
	now := fixedClock()
	p := newProgressTracker(SpinnerForge)
	p.start("nuclei", now)
	p.update(orchestrator.ModuleProgressEvent{Name: "nuclei", Current: 17, Total: 20, Unit: "pages"}, now)
	if view := p.view(now, 80, newTheme(false)); !strings.Contains(view, "17/20 pages") {
		t.Errorf("counts lost behind the spinner: %q", view)
	}
}

func TestStyledSpinnerKeepsDisplayWidth(t *testing.T) {
	now := fixedClock()
	th := newTheme(true)
	for _, style := range []SpinnerStyle{SpinnerForge, SpinnerDots} {
		for i := 0; i < 6; i++ {
			styled := style.styledFrame(now.Add(time.Duration(i)*spinnerInterval), th)
			plain := style.frame(now.Add(time.Duration(i) * spinnerInterval))
			if ansi.StringWidth(styled) != ansi.StringWidth(plain) {
				t.Errorf("style %d frame %d: styled width %d != plain width %d (%q)",
					style, i, ansi.StringWidth(styled), ansi.StringWidth(plain), styled)
			}
			if !strings.ContainsRune(styled, '\x1b') {
				t.Errorf("style %d frame %d lost its color: %q", style, i, styled)
			}
		}
	}
}
