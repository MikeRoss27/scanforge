package console

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
)

func TestGeneratedForgeHasStableAnvilAndDistinctPoses(t *testing.T) {
	seen := map[[forgeHeight][forgeWidth]int]bool{}
	colors := map[int]bool{}
	for _, frame := range forgePixels {
		seen[frame] = true
		for y, row := range frame {
			for _, c := range row {
				colors[c] = true
			}
			if y >= 8 && row != forgePixels[0][y] {
				t.Fatalf("anvil moved on row %d", y)
			}
		}
	}
	if len(seen) < 5 {
		t.Fatalf("only %d distinct hammer poses", len(seen))
	}
	if len(colors) < 5 {
		t.Fatalf("generated sprite lost its palette: %v", colors)
	}
}

func TestGeneratedForgeTerminalRows(t *testing.T) {
	for _, th := range []theme{{}, {enabled: true}, {enabled: true, truecolor: true}} {
		for i := 0; i < forgeCycleFrames; i++ {
			rows := forgeLoadingRows(time.Unix(0, int64(i)*int64(forgeAnimationInterval)), th)
			if len(rows) != 6 {
				t.Fatalf("sprite occupies %d rows, want 6", len(rows))
			}
			for _, row := range rows {
				if ansi.StringWidth(row) != 16 {
					t.Fatalf("sprite row width=%d, want 16", ansi.StringWidth(row))
				}
				if !th.enabled && strings.Contains(row, "\x1b") {
					t.Fatal("monochrome sprite leaked ANSI")
				}
			}
		}
	}
}

func TestForgeMotionHasFastContactAndContinuousLoop(t *testing.T) {
	if forgeHammerAngle(0) != forgeHammerAngle(forgeCycleFrames-1) {
		t.Fatal("loop jumps at seam")
	}
	for frame := 7; frame <= 11; frame++ {
		if forgeHammerAngle(frame) <= forgeHammerAngle(frame-1) {
			t.Fatalf("downswing reversed at %d", frame)
		}
	}
	for frame := 12; frame < 36; frame++ {
		if forgeHammerAngle(frame) >= forgeHammerAngle(frame-1) {
			t.Fatalf("return reversed at %d", frame)
		}
	}
	if forgeFrameIndex(time.Unix(0, 0)) != forgeFrameIndex(time.Unix(0, int64(forgeCycleFrames)*int64(forgeAnimationInterval))) {
		t.Fatal("cycle timing is inconsistent")
	}
}

type forgeWriteCounter struct{ calls int }

func (w *forgeWriteCounter) Write(p []byte) (int, error) {
	w.calls++
	return len(p), nil
}

func TestForgeRedrawUsesOneTerminalWrite(t *testing.T) {
	var writer forgeWriteCounter
	r := New(Options{Out: &writer, Terminal: Terminal{Tty: true, Volatile: true, Width: 80}, Verbosity: Normal, Clock: fixedClock})
	r.mu.Lock()
	defer r.mu.Unlock()
	r.progress.start("nuclei", fixedClock())
	r.redrawVolatileLocked()
	r.stopTickerLocked()
	writer.calls = 0
	r.redrawVolatileLocked()
	r.stopTickerLocked()
	if writer.calls != 1 {
		t.Fatalf("redraw used %d writes, want 1", writer.calls)
	}
	r.clearVolatileLocked()
}
