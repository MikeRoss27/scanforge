// Package report consolidates raw tool outputs into a unified risk model and
// renders report.json and report.md.
package report

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/storage"
)

// GenerateReport reads the manifest and runs appropriate parsers for each
// artifact. Parsing is best-effort: a corrupt or truncated tool output logs a
// warning and is skipped, so one bad artifact never discards the whole report.
func GenerateReport(runDir string, manifest *storage.RunManifest) (*Report, error) {
	rep := NewReport(manifest.Target, manifest.Profile)
	var warnings []error

	if t, err := time.Parse(time.RFC3339, manifest.StartedAt); err == nil {
		rep.StartedAt = t
	}
	if t, err := time.Parse(time.RFC3339, manifest.CompletedAt); err == nil {
		rep.CompletedAt = t
	}
	rep.Status = manifest.Status

	for key, relPath := range manifest.Outputs {
		// Only ever parse files inside the run directory. relPath comes from
		// the manifest, which modules write; an accidental traversal would
		// otherwise read arbitrary files into the report.
		absPath, err := runPath(runDir, relPath)
		if err != nil {
			warnings = append(warnings, err)
			continue
		}

		switch key {
		case "subfinder", "resolved_hosts":
			err = ParseHosts(absPath, rep)
		case "open_ports":
			err = ParsePorts(absPath, rep)
		case "httpx_raw":
			err = ParseHttpx(absPath, rep)
		case "dnsx_raw":
			err = ParseDnsx(absPath, rep)
		case "tls_raw":
			err = ParseTlsx(absPath, rep)
		case "nmap_xml":
			err = ParseNmapCollection(absPath, rep)
		case "whatweb_raw":
			err = ParseWhatWeb(absPath, rep)
		case "waf_raw":
			err = ParseWAF(absPath, rep)
		case "discovered_paths":
			err = ParseFfuf(absPath, rep)
		case "crawled_urls", "historical_urls":
			err = ParseKatana(absPath, rep)
		case "js_secrets":
			err = ParseJSSecrets(absPath, rep)
		case "js_verified":
			err = ParseJSVerify(absPath, rep)
		case "nuclei_raw":
			err = ParseNuclei(absPath, rep)
		case "cve_findings":
			err = ParseTechCVE(absPath, rep)
		case "http_checks":
			err = ParseHTTPChecks(absPath, rep)
		case "screenshots":
			err = ParseScreenshots(absPath, rep)
		}
		if err != nil {
			warnings = append(warnings, fmt.Errorf("failed to parse %s: %w", key, err))
		}
	}

	return rep, errors.Join(warnings...)
}

// runPath resolves a manifest-relative path inside runDir and rejects anything
// that would escape it.
func runPath(runDir, relPath string) (string, error) {
	clean := filepath.Clean(relPath)
	if clean == "." || filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
		return "", fmt.Errorf("refusing manifest path %q outside the run directory", relPath)
	}
	return filepath.Join(runDir, clean), nil
}
