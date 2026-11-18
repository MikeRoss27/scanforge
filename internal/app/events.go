package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	"github.com/MikeRoss27/scanforge/internal/storage"
	"github.com/MikeRoss27/scanforge/internal/tui"
	"github.com/MikeRoss27/scanforge/internal/ui"
)

// consumeEvents renders scan progress and waits for the run to exit.
// Diagnostic output can write directly to the terminal in verbose mode, so
// that mode uses plain logs to keep the output readable.
func (s *runSession) consumeEvents(cancel context.CancelFunc, eventChan <-chan orchestrator.Event, done <-chan struct{}) error {
	if !s.opts.DryRun && !s.opts.Verbose && os.Getenv("TERM") != "dumb" && term.IsTerminal(int(os.Stdout.Fd())) {
		model := tui.NewScanModel(eventChan)
		_, err := tea.NewProgram(model).Run()
		cancel()
		drainEvents(eventChan)
		<-done
		return err
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
	case orchestrator.ModuleStartEvent:
		if s.opts.Verbose {
			ui.Info("Running module %q...", e.Name)
		}
	case orchestrator.ModuleDoneEvent:
		if s.opts.Verbose || !s.opts.DryRun {
			fmt.Println(tui.FormatEvent(e))
		}
	default:
		if line := tui.FormatEvent(event); line != "" {
			fmt.Println(line)
		}
	}
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
