package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ListRuns returns every run found under workspace (runs/<target>/<id>),
// newest first. Directories without a readable manifest are ignored.
func ListRuns(workspace string) ([]*Run, error) {
	targets, err := os.ReadDir(workspace)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read workspace %q: %w", workspace, err)
	}
	var runs []*Run
	for _, target := range targets {
		if !target.IsDir() {
			continue
		}
		ids, err := os.ReadDir(filepath.Join(workspace, target.Name()))
		if err != nil {
			continue
		}
		for _, id := range ids {
			if !id.IsDir() {
				continue
			}
			run, err := OpenRun(filepath.Join(workspace, target.Name(), id.Name()))
			if err != nil {
				continue
			}
			runs = append(runs, run)
		}
	}
	sort.SliceStable(runs, func(i, j int) bool {
		if runs[i].Manifest.StartedAt != runs[j].Manifest.StartedAt {
			return runs[i].Manifest.StartedAt > runs[j].Manifest.StartedAt
		}
		return runs[i].RootDir > runs[j].RootDir
	})
	return runs, nil
}

// FindRun resolves a run reference: a run directory path, "<target>/<id>"
// relative to workspace, or a bare run ID. A bare ID shared by several
// targets is ambiguous and reported as an error listing the candidates.
func FindRun(workspace, ref string) (*Run, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, fmt.Errorf("run id is required")
	}
	for _, candidate := range []string{ref, filepath.Join(workspace, ref)} {
		if _, err := os.Stat(filepath.Join(candidate, ManifestRelPath)); err == nil {
			return OpenRun(candidate)
		}
	}
	runs, err := ListRuns(workspace)
	if err != nil {
		return nil, err
	}
	var matches []*Run
	for _, run := range runs {
		if filepath.Base(run.RootDir) == ref || run.ID == ref {
			matches = append(matches, run)
		}
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("run %q not found under %q", ref, workspace)
	case 1:
		return matches[0], nil
	}
	var where []string
	for _, m := range matches {
		where = append(where, m.RootDir)
	}
	return nil, fmt.Errorf("run id %q is ambiguous, use <target>/<id>: %s", ref, strings.Join(where, ", "))
}
