package app

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

func TestResumeDurationExcludesIdleGap(t *testing.T) {
	root := t.TempDir()
	app := New(writeTestConfig(t, root))
	if err := app.Run(context.Background(), RunOptions{Target: "example.com", Profile: "passive", DryRun: true, ConfirmScope: true}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	run, err := storage.OpenRun(firstRunDir(t, root))
	if err != nil {
		t.Fatal(err)
	}
	if run.Manifest.ActiveSeconds <= 0 {
		t.Fatalf("first segment active time not recorded: %+v", run.Manifest.ActiveSeconds)
	}

	// Simulate: interrupted after 5 active seconds, resumed two hours later.
	run.Manifest.StartedAt = time.Now().Add(-2 * time.Hour).Format(time.RFC3339)
	run.Manifest.ActiveSeconds = 5
	run.Manifest.Status = "running"
	run.Manifest.Modules[len(run.Manifest.Modules)-1].Status = storage.ModuleRunning
	if err := run.WriteManifest(); err != nil {
		t.Fatal(err)
	}
	if err := app.Resume(context.Background(), ResumeOptions{Run: run.ID}); err != nil {
		t.Fatalf("Resume() error = %v", err)
	}
	resumed, err := storage.OpenRun(run.RootDir)
	if err != nil {
		t.Fatal(err)
	}
	got := resumed.Manifest.ActiveDuration()
	if got < 5*time.Second || got > time.Minute {
		t.Fatalf("active duration after resume = %s, want ~5s (idle 2h excluded)", got)
	}
	summary := buildSummary(resumed, []*modules.Result{}, nil, false)
	if summary.Duration != got {
		t.Fatalf("summary duration = %s, want %s", summary.Duration, got)
	}
}

func TestFinalizeManifestAccumulatesSegments(t *testing.T) {
	dir := t.TempDir()
	s := &runSession{scanRun: &storage.Run{
		RootDir:      dir,
		ManifestPath: filepath.Join(dir, "manifest.json"),
		Manifest:     storage.RunManifest{Outputs: map[string]string{}, ActiveSeconds: 10},
	}, segmentStart: time.Now().Add(-3 * time.Second)}
	if err := s.finalizeManifest(nil, nil); err != nil {
		t.Fatal(err)
	}
	got := s.scanRun.Manifest.ActiveSeconds
	if got < 12.9 || got > 14 {
		t.Fatalf("ActiveSeconds = %v, want 10 + ~3", got)
	}
}

func TestManifestDurationBackwardCompatible(t *testing.T) {
	start := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	legacy := storage.RunManifest{
		StartedAt:   start.Format(time.RFC3339),
		CompletedAt: start.Add(90 * time.Second).Format(time.RFC3339),
	}
	if got := legacy.ActiveDuration(); got != 90*time.Second {
		t.Fatalf("legacy ActiveDuration = %s", got)
	}
	killed := storage.RunManifest{
		StartedAt: start.Format(time.RFC3339),
		UpdatedAt: start.Add(40 * time.Second).Format(time.RFC3339),
	}
	if got := killed.PriorActiveDuration(); got != 40*time.Second {
		t.Fatalf("killed-run PriorActiveDuration = %s", got)
	}
	tracked := storage.RunManifest{StartedAt: start.Format(time.RFC3339), ActiveSeconds: 7.5, CompletedAt: start.Add(time.Hour).Format(time.RFC3339)}
	if got := tracked.ActiveDuration(); got != 7500*time.Millisecond {
		t.Fatalf("tracked ActiveDuration = %s", got)
	}
}
