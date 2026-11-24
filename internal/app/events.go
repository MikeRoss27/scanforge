package app

import (
	"errors"
	"fmt"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

// consumeEvents streams orchestrator events into the console renderer until
// the scan ends. The terminal keeps its native scrollback: no fullscreen
// mode, no event draining, and the summary is printed by the same renderer
// so nothing can interleave.
func (s *runSession) consumeEvents(eventChan <-chan orchestrator.Event, done <-chan struct{}) {
	s.console.Consume(eventChan)
	<-done
}

// finalizeManifest records completion time, per-module results and the run
// status (completed/partial/failed) in the run manifest.
func (s *runSession) finalizeManifest(results []*modules.Result, runErr error) error {
	now := time.Now()
	s.scanRun.Manifest.CompletedAt = now.Format(time.RFC3339)
	if !s.segmentStart.IsZero() {
		s.scanRun.Manifest.AddActive(now.Sub(s.segmentStart))
		s.segmentStart = time.Time{}
	}
	completedModules, notApplicable := 0, 0
	for _, result := range results {
		switch {
		case result.Status == "completed":
			completedModules++
		case modules.IsNotApplicable(result):
			// The module skipped itself because there was nothing to do
			// (e.g. no WordPress host): that is a normal outcome, not a
			// reason to downgrade the run to partial.
			notApplicable++
		}
	}
	// A user-initiated abort is recorded as such, not as a failure.
	if errors.Is(runErr, orchestrator.ErrRunAborted) {
		s.scanRun.Manifest.Status = "aborted"
	} else {
		switch {
		case runErr == nil && completedModules+notApplicable == len(results):
			s.scanRun.Manifest.Status = "completed"
		case completedModules == 0:
			s.scanRun.Manifest.Status = "failed"
		default:
			s.scanRun.Manifest.Status = "partial"
		}
	}

	for _, result := range results {
		// The orchestrator already persisted a full checkpoint per module;
		// only fall back to a bare record when none exists.
		if _, ok := s.scanRun.Module(result.Name); !ok {
			s.scanRun.SetModule(storage.ModuleResult{Name: result.Name, Status: result.Status})
		}
		for key, value := range result.OutputFiles {
			s.scanRun.Manifest.Outputs[key] = value
		}
	}

	if err := s.scanRun.WriteManifest(); err != nil {
		return fmt.Errorf("failed to write run manifest: %w", err)
	}
	return nil
}
