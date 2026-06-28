package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type RunStore struct {
	Workspace string
}

type RunManifest struct {
	ID        string            `json:"id"`
	Target    string            `json:"target"`
	StartedAt string            `json:"started_at"`
	Status    string            `json:"status"`
	Outputs   map[string]string `json:"outputs"`
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
	id := time.Now().Format("2006-01-02_15-04-05")
	safeTarget := safeTargetName(target)

	rootDir := filepath.Join(s.Workspace, safeTarget, id)
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

func safeTargetName(target string) string {
	target = strings.TrimSpace(target)
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimSuffix(target, "/")

	re := regexp.MustCompile(`[^a-zA-Z0-9._-]+`)
	clean := re.ReplaceAllString(target, "_")

	if clean == "" {
		return "target"
	}

	return clean
}
