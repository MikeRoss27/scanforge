package ascii

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func TestForgePaletteFramesStayInsideCanvas(t *testing.T) {
	seen := map[string]bool{}
	for tick := 0; tick < 8; tick++ {
		plain := ForgeFrame(tick)
		seen[plain] = true
		for _, frame := range []string{plain, ColoredForgeFrame(tick, false), ColoredForgeFrame(tick, true)} {
			rows := strings.Split(frame, "\n")
			if len(rows) != 14 {
				t.Fatalf("frame %d has %d rows", tick, len(rows))
			}
			for _, row := range rows {
				if ansi.StringWidth(row) != 24 {
					t.Fatalf("frame %d: width %d", tick, ansi.StringWidth(row))
				}
			}
		}
		if strings.Contains(plain, "\x1b") {
			t.Fatal("plain frame leaked ANSI")
		}
	}
	if len(seen) < 4 {
		t.Fatal("hammer animation lost its distinct poses")
	}
	if !strings.Contains(ColoredForgeFrame(0, true), "38;2;") {
		t.Fatal("truecolor palette missing")
	}
	if !strings.Contains(ColoredForgeFrame(0, false), "38;5;") {
		t.Fatal("ANSI-256 palette missing")
	}
}

func TestBannerFitsTerminal(t *testing.T) {
	for _, width := range []int{40, 45, 46, 60, 80, 89, 90, 120} {
		art, tag, ok := Banner(width)
		if !ok {
			t.Fatalf("no banner for %d", width)
		}
		for _, row := range strings.Split(art+"\n"+tag, "\n") {
			if ansi.StringWidth(row) > width {
				t.Fatalf("banner exceeds %d columns", width)
			}
		}
	}
}
