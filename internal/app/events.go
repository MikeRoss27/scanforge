package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	"github.com/MikeRoss27/scanforge/internal/storage"
	"github.com/MikeRoss27/scanforge/internal/tui"
	"github.com/MikeRoss27/scanforge/internal/ui"
)

// consumeEvents renders scan progress either through the Bubble Tea TUI (when
// the output is a terminal and the run is real) or as plain log lines, and
// returns once the orchestrator goroutine has finished. A non-nil error means
// the TUI itself failed and the scan was aborted.
func (s *runSession) consumeEvents(cancel context.CancelFunc, eventChan <-chan orchestrator.Event, done <-chan struct{}) error {
	if !s.opts.DryRun && term.IsTerminal(int(os.Stdout.Fd())) {
		model := tui.NewScanModel(eventChan)
		if _, err := tea.NewProgram(model).Run(); err != nil {
			cancel()
			drainEvents(eventChan)
			<-done
			return err
		}
		// Replay warnings collected in the scan view; once the TUI is gone
		// nothing else would surface them.
		for _, warning := range model.Warnings() {
			ui.Warn("%s", warning)
		}
		// The user may have quit the UI before the scan finished: cancel the
		// run and drain the remaining events so the orchestrator can return.
		cancel()
		drainEvents(eventChan)
		<-done
		return nil
	}
	for event := range eventChan {
		s.printEvent(event)
	}
	<-done
	return nil
}

// drainEvents discards remaining orchestrator events in the background so the
// orchestrator can unblock and return after the TUI has gone away.
func drainEvents(eventChan <-chan orchestrator.Event) {
	go func() {
		for range eventChan {
		}
	}()
}

func (s *runSession) printEvent(event orchestrator.Event) {
	switch e := event.(type) {
	case orchestrator.WaveStartEvent:
		fmt.Println(ui.WaveHeader(e.Wave, strings.Join(e.Modules, ", ")))
	case orchestrator.ModuleStartEvent:
		if s.opts.Verbose {
			ui.Info("Running module %q...", e.Name)
		}
	case orchestrator.ModuleDoneEvent:
		if s.opts.Verbose || !s.opts.DryRun {
			printModuleResult(os.Stdout, e)
		}
	case orchestrator.DeadlockEvent:
		ui.Warn("%s", e.Message)
	case orchestrator.WarningEvent:
		ui.Warn("%s", e.Message)
	case orchestrator.FindingEvent:
		printFinding(e)
	}
}

// printFinding renders a finding the moment a module reports it, e.g.
// "  [nuclei] CRITICAL exposed-git-config · https://example.com/.git/config",
// so long-running scanners like nuclei don't leave the operator staring at a
// blank terminal for the module's entire duration.
func printFinding(e orchestrator.FindingEvent) {
	severity := e.Severity
	if severity == "" {
		severity = "info"
	}
	line := ui.Dim("["+e.Module+"]") + " " + ui.Severity(strings.ToUpper(severity)) + " " + ui.Bold(e.Title)
	if e.Target != "" {
		line += ui.Secondary(" · " + e.Target)
	}
	fmt.Println("  " + line)
}

// printModuleResult renders a compact, aligned completion line for a module,
// e.g. "  ✓ subfinder      2.1s · 8 subdomains". Skipped and aborted modules
// get their own mark and an explicit status: a module that never ran must
// never render like one that succeeded.
func printModuleResult(out io.Writer, e orchestrator.ModuleDoneEvent) {
	mark := "✓"
	color := ui.Green
	switch {
	case e.Failed:
		mark = "✗"
		color = ui.Red
	case e.Status == "skipped":
		mark = "↓"
		color = ui.Yellow
	case e.Status == "aborted":
		mark = "◌"
		color = ui.Orange
	}
	name := color(ui.Bold(fmt.Sprintf("%-13s", e.Name)))

	var parts []string
	if e.Dur > 0 {
		parts = append(parts, ui.Dim(e.Dur.Round(time.Millisecond).String()))
	}
	switch {
	case e.Failed && e.Status != "" && e.Status != "failed":
		parts = append(parts, ui.Red(e.Status))
	case e.Failed:
		parts = append(parts, ui.Red("failed"))
	case e.Status == "skipped":
		parts = append(parts, ui.Dim("skipped (dependency missing)"))
	case e.Status == "aborted":
		parts = append(parts, ui.Orange("aborted"))
	case e.Summary != "":
		parts = append(parts, ui.Secondary(e.Summary))
	}

	line := fmt.Sprintf("  %s %s", color(mark), name)
	if len(parts) > 0 {
		line += " " + strings.Join(parts, " · ")
	}
	_, _ = fmt.Fprintln(out, line)
}

// finalizeManifest records completion time, per-module results and the run
// status (completed/partial/failed) in the run manifest.
func (s *runSession) finalizeManifest(results []*modules.Result, runErr error) error {
	s.scanRun.Manifest.CompletedAt = time.Now().Format(time.RFC3339)
	completedModules := 0
	for _, result := range results {
		if result.Status == "completed" {
			completedModules++
		}
	}
	// A user-initiated abort is recorded as such, not as a failure.
	if errors.Is(runErr, orchestrator.ErrRunAborted) {
		s.scanRun.Manifest.Status = "aborted"
	} else {
		switch {
		case runErr == nil && completedModules == len(results):
			s.scanRun.Manifest.Status = "completed"
		case completedModules == 0:
			s.scanRun.Manifest.Status = "failed"
		default:
			s.scanRun.Manifest.Status = "partial"
		}
	}

	for _, result := range results {
		s.scanRun.Manifest.Modules = append(s.scanRun.Manifest.Modules, storage.ModuleResult{
			Name:   result.Name,
			Status: result.Status,
		})
		for key, value := range result.OutputFiles {
			s.scanRun.Manifest.Outputs[key] = value
		}
	}

	return s.scanRun.WriteManifest()
}
