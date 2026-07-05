package report

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/MikeRoss27/scanforge/internal/storage"
)

// GenerateReport reads the manifest and runs appropriate parsers for each artifact.
func GenerateReport(runDir string, manifest *storage.RunManifest) (*Report, error) {
	rep := NewReport(manifest.Target, manifest.Profile)
	
	if t, err := time.Parse(time.RFC3339, manifest.StartedAt); err == nil {
		rep.StartedAt = t
	}
	if t, err := time.Parse(time.RFC3339, manifest.CompletedAt); err == nil {
		rep.CompletedAt = t
	}
	rep.Status = manifest.Status

	for key, relPath := range manifest.Outputs {
		absPath := filepath.Join(runDir, relPath)
		
		switch key {
		case "subfinder", "resolved_hosts":
			if err := ParseHosts(absPath, rep); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %w", key, err)
			}
		case "open_ports":
			if err := ParsePorts(absPath, rep); err != nil {
				return nil, fmt.Errorf("failed to parse ports: %w", err)
			}
		case "httpx_raw":
			if err := ParseHttpx(absPath, rep); err != nil {
				return nil, fmt.Errorf("failed to parse httpx: %w", err)
			}
		case "discovered_paths":
			if err := ParseFfuf(absPath, rep); err != nil {
				return nil, fmt.Errorf("failed to parse ffuf: %w", err)
			}
		case "crawled_urls":
			if err := ParseKatana(absPath, rep); err != nil {
				return nil, fmt.Errorf("failed to parse katana: %w", err)
			}
		case "nuclei_raw":
			if err := ParseNuclei(absPath, rep); err != nil {
				return nil, fmt.Errorf("failed to parse nuclei: %w", err)
			}
		}
	}

	return rep, nil
}
