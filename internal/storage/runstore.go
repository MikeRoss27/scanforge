// Package storage manages run directories, manifests and artifact layout.
package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type RunStore struct {
	Workspace string
}

// Module checkpoint states recorded in the manifest. "aborted" results from
// the orchestrator are stored as ModuleCancelled.
const (
	ModulePending   = "pending"
	ModuleRunning   = "running"
	ModuleCompleted = "completed"
	ModuleFailed    = "failed"
	ModuleSkipped   = "skipped"
	ModuleCancelled = "cancelled"
)

// ArtifactRef is the persisted form of a published artifact, enough to
// re-publish it (through the scope filter) when a module is restored from a
// checkpoint.
type ArtifactRef struct {
	Type   string `json:"type"`
	Path   string `json:"path"`
	Scoped bool   `json:"scoped,omitempty"`
}

// ModuleResult is one module's checkpoint. Only Name and Status are
// required; the remaining fields are written by the orchestrator and make a
// run resumable.
type ModuleResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	// InputHash is the sha256 of everything that determines the module's
	// output (scope, parameters, tool version, required artifact contents).
	InputHash   string                 `json:"input_hash,omitempty"`
	StartedAt   string                 `json:"started_at,omitempty"`
	FinishedAt  string                 `json:"finished_at,omitempty"`
	Reason      string                 `json:"reason,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Artifacts   map[string]ArtifactRef `json:"artifacts,omitempty"`
	OutputFiles map[string]string      `json:"output_files,omitempty"`
}

// RunParams are the non-secret inputs of a run, persisted so `resume` can
// rebuild the same pipeline. Proxy and headers are deliberately not stored
// (they may carry credentials); resume callers pass them again and they are
// part of each module's input hash.
type RunParams struct {
	Modules []string        `json:"modules,omitempty"`
	Options json.RawMessage `json:"options,omitempty"`
}

type RunManifest struct {
	ID          string            `json:"id"`
	Target      string            `json:"target"`
	Profile     string            `json:"profile"`
	ScopePath   string            `json:"scope_path,omitempty"`
	ScopeSource string            `json:"scope_source,omitempty"`
	ScopeMode   string            `json:"scope_mode,omitempty"`
	StartedAt   string            `json:"started_at"`
	CompletedAt string            `json:"completed_at,omitempty"`
	Status      string            `json:"status"`
	Modules     []ModuleResult    `json:"modules,omitempty"`
	Outputs     map[string]string `json:"outputs"`
	Artifacts   map[string]string `json:"artifacts,omitempty"`
	DryRun      bool              `json:"dry_run,omitempty"`
	// ScopeSHA256 is the digest of 00_meta/effective-scope.txt at run
	// creation; resume refuses to continue if the file no longer matches,
	// so a resumed run can never use a widened scope.
	ScopeSHA256 string     `json:"scope_sha256,omitempty"`
	Params      *RunParams `json:"params,omitempty"`
	ResumeCount int        `json:"resume_count,omitempty"`
	UpdatedAt   string     `json:"updated_at,omitempty"`
}

type Run struct {
	ID           string
	Target       string
	RootDir      string
	MetaDir      string
	CommandsLog  string
	ManifestPath string
	Manifest     RunManifest

	// mu serializes manifest mutations and writes: modules finish
	// concurrently and each state change is persisted immediately.
	mu sync.Mutex
}

func NewRunStore(workspace string) *RunStore {
	return &RunStore{
		Workspace: workspace,
	}
}

func (s *RunStore) Create(target string) (*Run, error) {
	safeTarget := safeTargetName(target)

	// Two runs started within the same second must not share a directory, so
	// append a numeric suffix until the path is free.
	baseID := time.Now().Format("2006-01-02_15-04-05")
	id := baseID
	rootDir := filepath.Join(s.Workspace, safeTarget, id)
	for suffix := 2; ; suffix++ {
		if _, err := os.Stat(rootDir); os.IsNotExist(err) {
			break
		}
		id = fmt.Sprintf("%s-%d", baseID, suffix)
		rootDir = filepath.Join(s.Workspace, safeTarget, id)
	}
	metaDir := filepath.Join(rootDir, "00_meta")

	dirs := []string{
		metaDir,
		filepath.Join(rootDir, "01_subdomains"),
		filepath.Join(rootDir, "02_http"),
		filepath.Join(rootDir, "03_ports"),
		filepath.Join(rootDir, "04_web"),
		filepath.Join(rootDir, "05_content"),
		filepath.Join(rootDir, "06_vulns"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}
	}

	run := &Run{
		ID:           id,
		Target:       target,
		RootDir:      rootDir,
		MetaDir:      metaDir,
		CommandsLog:  filepath.Join(metaDir, "commands.log"),
		ManifestPath: filepath.Join(metaDir, "manifest.json"),
		Manifest: RunManifest{
			ID:        id,
			Target:    target,
			StartedAt: time.Now().Format(time.RFC3339),
			Status:    "created",
			Outputs: map[string]string{
				"commands_log": "00_meta/commands.log",
			},
		},
	}

	if err := run.WriteManifest(); err != nil {
		return nil, err
	}

	return run, nil
}

func (r *Run) Path(parts ...string) string {
	all := append([]string{r.RootDir}, parts...)
	return filepath.Join(all...)
}

// WriteManifest persists the manifest atomically (temp file in the same
// directory + rename), so an interrupted process never leaves a truncated
// manifest behind.
func (r *Run) WriteManifest() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.writeManifestLocked()
}

func (r *Run) writeManifestLocked() error {
	r.Manifest.UpdatedAt = time.Now().Format(time.RFC3339)
	data, err := json.MarshalIndent(r.Manifest, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(r.ManifestPath, data, 0644)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".manifest-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		return fail(err)
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return fail(err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fail(err)
	}
	return nil
}

// Module returns the checkpoint recorded for name.
func (r *Run) Module(name string) (ModuleResult, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.Manifest.Modules {
		if m.Name == name {
			return m, true
		}
	}
	return ModuleResult{}, false
}

// ModuleRecords returns a snapshot of every module checkpoint.
func (r *Run) ModuleRecords() []ModuleResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]ModuleResult(nil), r.Manifest.Modules...)
}

// SetModule upserts a module checkpoint in memory, keeping first-seen order.
func (r *Run) SetModule(rec ModuleResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.setModuleLocked(rec)
}

func (r *Run) setModuleLocked(rec ModuleResult) {
	for i := range r.Manifest.Modules {
		if r.Manifest.Modules[i].Name == rec.Name {
			r.Manifest.Modules[i] = rec
			return
		}
	}
	r.Manifest.Modules = append(r.Manifest.Modules, rec)
}

// UpdateModule upserts a module checkpoint and atomically persists the
// manifest. The orchestrator calls it on every module state change.
func (r *Run) UpdateModule(rec ModuleResult) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.setModuleLocked(rec)
	return r.writeManifestLocked()
}

// ManifestRelPath is the manifest location relative to a run root directory.
const ManifestRelPath = "00_meta/manifest.json"

// LatestRun opens the most recently created run for target under workspace
// (the same directory Create would use for it). Run IDs are formatted
// "2006-01-02_15-04-05[-N]" (see Create), which sorts lexicographically in
// time order for any realistic run cadence; the one known gap is two or
// more collisions in the very same second for the very same target, where
// a "-10"+ suffix would sort before "-9" — harmless in practice (Create
// itself only expects same-second collisions to be rare) and not worth
// padding the suffix for.
//
// Callers that just ran a target (the benchmark command, in particular)
// use this instead of threading the *storage.Run back out of app.Run,
// which only ever returns an error.
func LatestRun(workspace, target string) (*Run, error) {
	parent := filepath.Join(workspace, safeTargetName(target))
	entries, err := os.ReadDir(parent)
	if err != nil {
		return nil, fmt.Errorf("no runs found for target %q under %q: %w", target, workspace, err)
	}

	var latest string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if entry.Name() > latest {
			latest = entry.Name()
		}
	}
	if latest == "" {
		return nil, fmt.Errorf("no run directories found for target %q under %q", target, parent)
	}
	return OpenRun(filepath.Join(parent, latest))
}

// OpenRun loads an existing run directory (a rootDir pointing at a
// runs/<target>/<id> folder) by reading its manifest back from disk. The
// manifest is authoritative: every other path is derived from it.
func OpenRun(rootDir string) (*Run, error) {
	manifestPath := filepath.Join(rootDir, ManifestRelPath)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read manifest %s: %w", manifestPath, err)
	}
	var manifest RunManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse manifest %s: %w", manifestPath, err)
	}
	metaDir := filepath.Join(rootDir, "00_meta")
	return &Run{
		ID:           manifest.ID,
		Target:       manifest.Target,
		RootDir:      rootDir,
		MetaDir:      metaDir,
		CommandsLog:  filepath.Join(metaDir, "commands.log"),
		ManifestPath: manifestPath,
		Manifest:     manifest,
	}, nil
}

// safeTargetName turns a target into a filesystem-safe directory label. The
// cleaned label must never be "." or ".." or contain a ".." path element,
// otherwise filepath.Join could escape the workspace.
func safeTargetName(target string) string {
	target = strings.TrimSpace(target)
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimSuffix(target, "/")

	re := regexp.MustCompile(`[^a-zA-Z0-9._-]+`)
	clean := re.ReplaceAllString(target, "_")

	if clean == "" || clean == "." || clean == ".." || strings.Contains(clean, "..") {
		return "target"
	}

	return clean
}
