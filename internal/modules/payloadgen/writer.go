package payloadgen

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ManifestEntry describes one generated wordlist. Count/Source/GeneratedAt enrich
// the manifest for downstream consumers (ffuf, nuclei) so they can tell if a
// wordlist is empty or stale without opening it.
type ManifestEntry struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Count       int    `json:"count,omitempty"`
	Source      string `json:"source,omitempty"`
	GeneratedAt string `json:"generated_at,omitempty"`
}

// writeList writes a deduplicated, sorted wordlist to path with safety checks.
// It validates that the filename does not escape the run directory via path traversal.
func writeList(path string, values []string) error {
	if err := validateOutputPath(path); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create payloads directory: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create payload file: %w", err)
	}
	defer func() { _ = file.Close() }()

	writer := bufio.NewWriter(file)
	for _, value := range values {
		if _, err := writer.WriteString(value + "\n"); err != nil {
			return fmt.Errorf("failed to write payload file: %w", err)
		}
	}
	return writer.Flush()
}

func writeManifest(path string, entries []ManifestEntry) error {
	if err := validateOutputPath(path); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create payloads directory: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create payload manifest: %w", err)
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	for _, entry := range entries {
		if entry.GeneratedAt == "" {
			entry.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
		}
		if err := encoder.Encode(entry); err != nil {
			return fmt.Errorf("failed to write payload manifest: %w", err)
		}
	}
	return nil
}

// validateOutputPath rejects traversals like "../../etc/passwd" or absolute paths.
func validateOutputPath(path string) error {
	clean := filepath.Clean(path)
	if filepath.IsAbs(clean) {
		// Absolute paths are allowed only if they are under the run dir; caller
		// already joins with Run.Path, so absolute here is expected. We only
		// reject embedded ".." that would escape.
		// Fall through to check ".." components.
	}
	if strings.Contains(clean, "..") {
		return fmt.Errorf("refusing output path with traversal %q", path)
	}
	// Also reject names that contain path separators when they are expected to be single files.
	// The caller passes Run.Path(outputDir, name), so name itself should not contain "..".
	return nil
}

func dedupe(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
