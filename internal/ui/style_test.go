package ui

import (
	"strings"
	"testing"
)

func TestProgressBar(t *testing.T) {
	cases := []struct {
		completed, total, width int
	}{
		{0, 0, 20},
		{3, 5, 20},
		{5, 5, 20},
		{9, 5, 20}, // completed clamped to total
		{2, 0, 20}, // total falls back to completed
		{0, 3, 0},  // width falls back to default
	}
	for _, tc := range cases {
		bar := ProgressBar(tc.completed, tc.total, tc.width)
		if !strings.Contains(bar, "/") {
			t.Fatalf("ProgressBar(%d, %d, %d) = %q, want a count", tc.completed, tc.total, tc.width, bar)
		}
		if strings.Contains(bar, "�") {
			t.Fatalf("ProgressBar(%d, %d, %d) rendered garbage: %q", tc.completed, tc.total, tc.width, bar)
		}
	}
}
