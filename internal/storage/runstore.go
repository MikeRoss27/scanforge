// Package storage manages run directories, manifests and artifact layout.
package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type RunStore struct {
	Workspace string
}

type ModuleResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
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
}

type Run struct {
	ID           string
	Target       string
	RootDir      string
	MetaDir      string
	CommandsLog  string
	ManifestPath string
	Manifest     RunManifest
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

func (r *Run) WriteManifest() error {
	data, err := json.MarshalIndent(r.Manifest, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(r.ManifestPath, data, 0644)
}

// ManifestRelPath is the manifest location relative to a run root directory.
const ManifestRelPath = "00_meta/manifest.json"

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
