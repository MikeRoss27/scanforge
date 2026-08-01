package orchestrator

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pterm/pterm"
	"golang.org/x/term"
)

// reporter surfaces module scheduling/execution progress to the terminal.
// Two implementations exist: a live one with a spinner per running module
// (interactive TTY, real runs) and a plain line-based one that degrades
// gracefully for dry runs, redirected output, and CI logs.
type reporter interface {
	waveStart(wave int, names []string)
	moduleStart(name string)
	moduleDone(name, status string, dur time.Duration, failed bool)
	deadlock(msg string)
	waveEnd()
}

// newReporter picks the live spinner UI for interactive, real (non-dry-run)
// runs, and falls back to plain lines otherwise — a live-redrawing spinner
// writes cursor-control escape codes that only make sense on a real
// terminal, so anything else (dry-run previews, `> file`, CI logs) gets the
// plain reporter instead.
func newReporter(verbose, dryRun bool) reporter {
	if !dryRun && isInteractiveStdout() {
		return newSpinnerReporter()
	}
	return &lineReporter{verbose: verbose, alwaysLog: !dryRun}
}

func isInteractiveStdout() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

type spinnerReporter struct {
	mu       sync.Mutex
	multi    pterm.MultiPrinter
	spinners map[string]*pterm.SpinnerPrinter
}

func newSpinnerReporter() *spinnerReporter {
	return &spinnerReporter{spinners: make(map[string]*pterm.SpinnerPrinter)}
}

func (r *spinnerReporter) waveStart(_ int, names []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.multi = pterm.DefaultMultiPrinter
	if _, err := r.multi.Start(); err != nil {
		return
	}
	for _, name := range names {
		spinner, err := pterm.DefaultSpinner.WithWriter(r.multi.NewWriter()).Start(name + ": running...")
		if err != nil {
			continue
		}
		r.spinners[name] = spinner
	}
}

func (r *spinnerReporter) moduleStart(string) {}

func (r *spinnerReporter) moduleDone(name, status string, dur time.Duration, failed bool) {
	r.mu.Lock()
	spinner := r.spinners[name]
	r.mu.Unlock()
	if spinner == nil {
		return
	}
	msg := fmt.Sprintf("%s: %s (%s)", name, status, dur.Round(time.Millisecond))
	if failed {
		spinner.Fail(msg)
	} else {
		spinner.Success(msg)
	}
}

func (r *spinnerReporter) deadlock(msg string) {
	pterm.Warning.Println(msg)
}

func (r *spinnerReporter) waveEnd() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := r.multi.Stop(); err != nil {
		return
	}
	r.spinners = make(map[string]*pterm.SpinnerPrinter)
}

type lineReporter struct {
	verbose   bool
	alwaysLog bool
}

func (r *lineReporter) enabled() bool { return r.alwaysLog || r.verbose }

func (r *lineReporter) waveStart(wave int, names []string) {
	if !r.enabled() {
		return
	}
	pterm.Info.Printfln("Wave %d: %s", wave, strings.Join(names, ", "))
}

func (r *lineReporter) moduleStart(name string) {
	if !r.verbose {
		return
	}
	pterm.Info.Printfln("Running module %q...", name)
}

func (r *lineReporter) moduleDone(name, status string, dur time.Duration, failed bool) {
	if !r.enabled() {
		return
	}
	msg := fmt.Sprintf("%s: %s (%s)", name, status, dur.Round(time.Millisecond))
	if failed {
		pterm.Error.Println(msg)
	} else {
		pterm.Success.Println(msg)
	}
}

func (r *lineReporter) deadlock(msg string) {
	pterm.Warning.Println(msg)
}

func (r *lineReporter) waveEnd() {}
