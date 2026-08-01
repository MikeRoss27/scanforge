package orchestrator

import (
	"testing"
	"time"
)

func TestNewReporterPicksLineReporterWhenNotInteractive(t *testing.T) {
	// go test's stdout is never a TTY, so this always exercises the
	// non-interactive fallback regardless of the machine running it.
	for _, dryRun := range []bool{true, false} {
		r := newReporter(true, dryRun)
		if _, ok := r.(*lineReporter); !ok {
			t.Fatalf("newReporter(dryRun=%v) = %T, want *lineReporter outside a TTY", dryRun, r)
		}
	}
}

func TestLineReporterDoesNotPanic(t *testing.T) {
	for _, r := range []reporter{
		&lineReporter{verbose: true, alwaysLog: true},
		&lineReporter{verbose: false, alwaysLog: true},
		&lineReporter{verbose: false, alwaysLog: false},
	} {
		r.waveStart(1, []string{"subfinder", "gau"})
		r.moduleStart("subfinder")
		r.moduleDone("subfinder", "completed", 10*time.Millisecond, false)
		r.moduleDone("gau", "failed", 5*time.Millisecond, true)
		r.deadlock("no more modules can run")
		r.waveEnd()
	}
}

func TestLineReporterEnabled(t *testing.T) {
	cases := []struct {
		name      string
		verbose   bool
		alwaysLog bool
		want      bool
	}{
		{"dry-run quiet", false, false, false},
		{"dry-run verbose", true, false, true},
		{"real run quiet", false, true, true},
		{"real run verbose", true, true, true},
	}
	for _, tc := range cases {
		r := &lineReporter{verbose: tc.verbose, alwaysLog: tc.alwaysLog}
		if got := r.enabled(); got != tc.want {
			t.Errorf("%s: enabled() = %v, want %v", tc.name, got, tc.want)
		}
	}
}
