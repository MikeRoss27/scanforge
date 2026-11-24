package app

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/MikeRoss27/scanforge/internal/assets"
	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/report"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

// incrementalState is the per-run state of the asset history: the history as
// read (and scope-filtered) before the run, the cache-invalidation verdict
// and the tool versions detected for this run.
type incrementalState struct {
	history      *assets.History
	invalidated  bool
	focused      bool
	toolVersions map[string]string
}

// prepareIncremental loads the target's asset history, drops every entry
// outside the current effective scope, decides whether the cache is still
// valid (same scope hash and tool versions as the last recorded run) and,
// for --incremental, returns the focus that narrows nuclei/ffuf/katana/
// jssecrets inputs. It returns a nil interface when the run is not
// incremental or the history cannot be used: the run then scans everything.
func (s *runSession) prepareIncremental() modules.InputFocus {
	if s.opts.DryRun {
		return nil
	}
	hist, err := assets.Load(assets.PathFor(s.scanRun.RootDir))
	if err != nil {
		s.console.Warn("asset history unreadable, treating every asset as new: %v", err)
		return nil
	}
	if dropped := hist.FilterScope(s.effective.value); dropped > 0 {
		s.console.Info("asset history: ignored %d entr(ies) outside the current scope", dropped)
	}
	s.incremental.history = hist
	s.incremental.invalidated = hist.Invalidated(s.scanRun.Manifest.ScopeSHA256, s.incremental.toolVersions)
	if !s.opts.Incremental {
		return nil
	}
	if s.incremental.invalidated {
		s.console.Info("incremental: scope or tool versions changed since the last run, treating every asset as new")
	} else if len(hist.Records) == 0 {
		s.console.Info("incremental: no asset history yet, full scan")
	} else {
		s.console.Info("incremental: nuclei, ffuf, katana and jssecrets will only look at new or changed URLs")
	}
	s.incremental.focused = !s.incremental.invalidated
	return assets.NewFocus(hist, s.incremental.invalidated, s.scanRun.Path("02_http", "httpx.jsonl"))
}

// recordAssets appends this run to runs/<target>/assets.jsonl from the final
// consolidated report. Only completed, real runs are recorded: a partial or
// dry run would make assets look gone (or new) for the wrong reasons.
func (s *runSession) recordAssets(rep *report.Report) {
	if s.opts.DryRun || rep == nil || s.reportErr != nil {
		return
	}
	if status := s.scanRun.Manifest.Status; status != "completed" {
		s.console.Warn("asset history not updated: run status is %q (only completed runs are recorded)", status)
		return
	}
	path := assets.PathFor(s.scanRun.RootDir)
	hist := s.incremental.history
	if hist == nil {
		var err error
		if hist, err = assets.Load(path); err != nil {
			s.console.Warn("asset history not updated: %v", err)
			return
		}
		hist.FilterScope(s.effective.value)
		s.incremental.invalidated = hist.Invalidated(s.scanRun.Manifest.ScopeSHA256, s.incremental.toolVersions)
	}
	if hist.HasRun(s.scanRun.ID) {
		return
	}
	completed := map[string]bool{}
	for _, rec := range s.scanRun.Manifest.Modules {
		if rec.Status == storage.ModuleCompleted {
			completed[rec.Name] = true
		}
	}
	recs := assets.Reconcile(hist, assets.Observe(rep), assets.RunMeta{
		RunID:        s.scanRun.ID,
		At:           time.Now(),
		ScopeSHA256:  s.scanRun.Manifest.ScopeSHA256,
		ToolVersions: s.incremental.toolVersions,
		Coverage:     assets.Coverage(completed, s.incremental.focused),
		Invalidated:  s.incremental.invalidated,
	})
	if err := assets.Append(path, recs); err != nil {
		s.console.Warn("asset history not updated: %v", err)
		return
	}
	counts := map[string]int{}
	for _, rec := range recs {
		if rec.Type != assets.TypeRun {
			counts[rec.Status]++
		}
	}
	s.console.Info("asset history updated: %d new, %d changed, %d unchanged, %d gone",
		counts[assets.StatusNew], counts[assets.StatusChanged], counts[assets.StatusUnchanged], counts[assets.StatusGone])
}

// AssetsOptions selects what `scanforge assets` lists.
type AssetsOptions struct {
	Target string
	// New and Gone restrict the listing to those statuses (both set lists
	// both).
	New  bool
	Gone bool
}

// Assets returns the current state of every asset recorded for a target.
func (a *App) Assets(opts AssetsOptions) ([]assets.Record, error) {
	cfg, err := a.loadConfig()
	if err != nil {
		return nil, err
	}
	return listAssets(storage.TargetDir(config.WorkspaceDir(cfg), opts.Target), opts)
}

func listAssets(targetDir string, opts AssetsOptions) ([]assets.Record, error) {
	path := filepath.Join(targetDir, assets.FileName)
	hist, err := assets.Load(path)
	if err != nil {
		return nil, err
	}
	if len(hist.Records) == 0 && hist.Last == nil {
		return nil, fmt.Errorf("no asset history for %q (expected %s; it is written after a completed run)", opts.Target, path)
	}
	var out []assets.Record
	for _, rec := range hist.Sorted() {
		switch {
		case !opts.New && !opts.Gone:
		case opts.New && rec.Status == assets.StatusNew:
		case opts.Gone && rec.Status == assets.StatusGone:
		default:
			continue
		}
		out = append(out, rec)
	}
	return out, nil
}
