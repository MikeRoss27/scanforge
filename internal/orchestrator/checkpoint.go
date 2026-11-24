package orchestrator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

// hashVersion is bumped whenever the composition of the input hash changes,
// which invalidates every older checkpoint.
const hashVersion = 1

// checkpointer persists per-module state into the run manifest and decides
// whether a previously completed module can be reused on resume. A nil run
// (unit tests that execute without a run directory) disables it entirely.
type checkpointer struct {
	run        *storage.Run
	runCtx     *modules.RunContext
	opts       Options
	scopeParts []string
	versions   map[string]string
	// prior is the manifest's module state as it was when the run was
	// opened; it is only consulted when opts.Resume is set.
	prior  map[string]storage.ModuleResult
	hashes map[string]string
	starts map[string]time.Time
}

func newCheckpointer(run *storage.Run, runCtx *modules.RunContext, opts Options, selected []modules.Module) *checkpointer {
	if run == nil || run.ManifestPath == "" {
		// No manifest to persist into (unit tests with a bare run).
		return nil
	}
	cp := &checkpointer{
		run:      run,
		runCtx:   runCtx,
		opts:     opts,
		versions: make(map[string]string, len(selected)),
		prior:    make(map[string]storage.ModuleResult),
		hashes:   make(map[string]string),
		starts:   make(map[string]time.Time),
	}
	if opts.Scope != nil {
		// Captured once, before any module can add a discovered host.
		cp.scopeParts = opts.Scope.Entries()
	}
	if opts.Resume {
		for _, rec := range run.ModuleRecords() {
			cp.prior[rec.Name] = rec
		}
	}
	for _, m := range selected {
		if opts.ToolVersion != nil {
			cp.versions[m.Name()] = opts.ToolVersion(m.Name())
		}
	}
	return cp
}

// seed records every selected module that has no checkpoint yet as pending.
// Existing records are kept untouched so an interrupted resume does not lose
// the ability to reuse earlier work.
func (cp *checkpointer) seed(selected []modules.Module) error {
	if cp == nil {
		return nil
	}
	for _, m := range selected {
		if _, ok := cp.run.Module(m.Name()); ok {
			continue
		}
		cp.run.SetModule(storage.ModuleResult{Name: m.Name(), Status: storage.ModulePending})
	}
	return cp.run.WriteManifest()
}

// inputHash digests everything that determines a module's output.
func (cp *checkpointer) inputHash(m modules.Module) string {
	required := append([]string(nil), m.Requires()...)
	if soft, ok := m.(modules.SoftRequires); ok {
		required = append(required, soft.SoftRequires()...)
	}
	sort.Strings(required)
	type artifactDigest struct {
		Name   string `json:"name"`
		Digest string `json:"digest"`
	}
	artifacts := make([]artifactDigest, 0, len(required))
	seen := make(map[string]bool, len(required))
	for _, name := range required {
		if seen[name] {
			continue
		}
		seen[name] = true
		artifacts = append(artifacts, artifactDigest{Name: name, Digest: cp.artifactDigest(name)})
	}
	payload := struct {
		Version  int              `json:"version"`
		Module   string           `json:"module"`
		Target   string           `json:"target"`
		Profile  string           `json:"profile"`
		DryRun   bool             `json:"dry_run"`
		Scope    []string         `json:"scope"`
		Params   any              `json:"params"`
		Tool     string           `json:"tool_version"`
		Required []artifactDigest `json:"required"`
	}{
		Version:  hashVersion,
		Module:   m.Name(),
		Target:   cp.opts.Target,
		Profile:  cp.opts.Profile,
		DryRun:   cp.opts.DryRun,
		Scope:    cp.scopeParts,
		Params:   moduleParams(m.Name(), cp.opts),
		Tool:     cp.versions[m.Name()],
		Required: artifacts,
	}
	data, _ := json.Marshal(payload)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// moduleParams selects the options that can influence a module's output:
// transport settings apply to everyone, tool tuning only to its own module.
func moduleParams(name string, opts Options) any {
	params := map[string]any{
		"proxy":   opts.Proxy,
		"headers": opts.Headers,
	}
	switch {
	case name == "nuclei":
		params["nuclei"] = opts.Nuclei
	case name == "ffuf":
		params["ffuf"] = opts.Ffuf
	case name == "nmap":
		params["nmap_concurrency"] = opts.NmapConcurrency
	case strings.HasPrefix(name, "wp"):
		params["wordpress"] = opts.WordPress
	}
	if opts.InputFocus != nil {
		switch name {
		case "nuclei", "ffuf", "katana", "jssecrets":
			// A result computed under another incremental focus (or none)
			// must not be reused on resume.
			params["incremental_focus"] = opts.InputFocus.Digest()
		}
	}
	if opts.Config != nil {
		if timeout := opts.Config.ModuleTimeouts[name]; timeout > 0 {
			params["timeout"] = timeout.String()
		}
	}
	return params
}

// artifactDigest hashes the content of a published artifact (file or
// directory tree). Unpublished or missing artifacts get stable sentinels.
func (cp *checkpointer) artifactDigest(name string) string {
	art, ok := cp.runCtx.GetArtifact(name)
	if !ok {
		return "absent"
	}
	return digestPath(cp.run.Path(art.Path))
}

func digestPath(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "missing"
	}
	h := sha256.New()
	if !info.IsDir() {
		if err := hashFile(h, path); err != nil {
			return "unreadable"
		}
		return hex.EncodeToString(h.Sum(nil))
	}
	_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(path, p)
		_, _ = io.WriteString(h, filepath.ToSlash(rel)+"\x00")
		_ = hashFile(h, p)
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))
}

func hashFile(h io.Writer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = io.Copy(h, f)
	return err
}

// restore reports whether m can be reused from the previous run: it must
// have finished (completed, or skipped by itself as not applicable) with an
// identical input hash and every recorded output must still exist. When it
// can, its artifacts are re-published through RunContext.AddArtifact, so the
// scope filter is applied to them again.
func (cp *checkpointer) restore(m modules.Module, hash string) (*modules.Result, bool) {
	if cp == nil || !cp.opts.Resume {
		return nil, false
	}
	rec, ok := cp.prior[m.Name()]
	if !ok || rec.InputHash == "" || rec.InputHash != hash {
		return nil, false
	}
	reusable := rec.Status == storage.ModuleCompleted ||
		(rec.Status == storage.ModuleSkipped && rec.Reason != "")
	if !reusable {
		return nil, false
	}
	for _, ref := range rec.Artifacts {
		if _, err := os.Stat(cp.run.Path(ref.Path)); err != nil {
			return nil, false
		}
	}
	for _, rel := range rec.OutputFiles {
		if rel == "" || filepath.IsAbs(rel) || strings.Contains(rel, "..") {
			continue
		}
		if _, err := os.Stat(cp.run.Path(rel)); err != nil {
			return nil, false
		}
	}
	for name, ref := range rec.Artifacts {
		art := modules.Artifact{Name: name, Type: ref.Type, Path: ref.Path, Scoped: ref.Scoped}
		if err := cp.runCtx.AddArtifact(name, art); err != nil {
			return nil, false
		}
	}
	status := rec.Status
	return &modules.Result{
		Name:        m.Name(),
		Status:      status,
		OutputFiles: rec.OutputFiles,
		Reason:      rec.Reason,
	}, true
}

// started records the module as running (persisted immediately).
func (cp *checkpointer) started(m modules.Module, hash string) {
	if cp == nil {
		return
	}
	now := time.Now()
	cp.hashes[m.Name()] = hash
	cp.starts[m.Name()] = now
	_ = cp.run.UpdateModule(storage.ModuleResult{
		Name:      m.Name(),
		Status:    storage.ModuleRunning,
		InputHash: hash,
		StartedAt: now.Format(time.RFC3339),
	})
}

// finished records a module's terminal state with the artifacts it
// published, persisted immediately.
func (cp *checkpointer) finished(m modules.Module, result *modules.Result, err error) {
	if cp == nil || result == nil {
		return
	}
	if _, launched := cp.hashes[m.Name()]; !launched {
		// Never reached in this invocation (aborted or dependency skip):
		// keep an earlier reusable checkpoint instead of erasing it.
		if prior, ok := cp.prior[m.Name()]; ok && prior.Status == storage.ModuleCompleted {
			return
		}
	}
	rec := storage.ModuleResult{
		Name:        m.Name(),
		Status:      manifestStatus(result.Status),
		InputHash:   cp.hashes[m.Name()],
		FinishedAt:  time.Now().Format(time.RFC3339),
		Reason:      result.Reason,
		OutputFiles: cp.existingOutputs(result.OutputFiles),
	}
	if started, ok := cp.starts[m.Name()]; ok {
		rec.StartedAt = started.Format(time.RFC3339)
	}
	if err != nil {
		rec.Error = err.Error()
	}
	if rec.Status == storage.ModuleCompleted || rec.Status == storage.ModuleSkipped {
		for _, name := range m.Produces() {
			if art, ok := cp.runCtx.GetArtifact(name); ok {
				if rec.Artifacts == nil {
					rec.Artifacts = make(map[string]storage.ArtifactRef)
				}
				rec.Artifacts[name] = storage.ArtifactRef{Type: art.Type, Path: art.Path, Scoped: art.Scoped}
			}
		}
	}
	// A restored (cached) module keeps its original timestamps.
	if prior, ok := cp.prior[m.Name()]; ok && prior.InputHash == rec.InputHash && rec.StartedAt == "" {
		rec.StartedAt, rec.FinishedAt = prior.StartedAt, prior.FinishedAt
	}
	_ = cp.run.UpdateModule(rec)
}

// existingOutputs drops declared output files that were never written (a
// stderr log of a command that was skipped, an empty payload list...). They
// would otherwise make restore() consider the checkpoint damaged and re-run a
// perfectly complete module on every resume. Dry runs write nothing, so their
// declarations are kept as is.
func (cp *checkpointer) existingOutputs(files map[string]string) map[string]string {
	if cp.opts.DryRun || len(files) == 0 {
		return files
	}
	kept := make(map[string]string, len(files))
	for key, rel := range files {
		if rel != "" && !filepath.IsAbs(rel) && !strings.Contains(rel, "..") {
			if _, err := os.Stat(cp.run.Path(rel)); err != nil {
				continue
			}
		}
		kept[key] = rel
	}
	return kept
}

// manifestStatus maps an orchestrator result status to a checkpoint state.
func manifestStatus(status string) string {
	switch status {
	case "aborted":
		return storage.ModuleCancelled
	case "":
		return storage.ModuleFailed
	default:
		return status
	}
}
