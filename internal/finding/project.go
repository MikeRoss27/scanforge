package finding

import (
	"net/url"
	"sort"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/report"
)

// FromReport projects the consolidated report into the flat, canonical
// finding model. Every vulnerability (nuclei, techcve, http checks, js
// secrets) becomes a Finding with a deterministic ID; verified JS secret
// replays become findings of kind "verified_secret". The projection is
// deterministic: assets are visited in sorted order and findings keep the
// order they appear in the report.
func FromReport(rep *report.Report) []Finding {
	if rep == nil {
		return nil
	}

	assets := make([]string, 0, len(rep.Assets))
	for name := range rep.Assets {
		assets = append(assets, name)
	}
	sort.Strings(assets)

	var findings []Finding
	for _, name := range assets {
		asset := rep.Assets[name]
		for _, vuln := range asset.Vulnerabilities {
			f := Finding{
				Kind:        "vulnerability",
				Asset:       name,
				URL:         urlIfHTTP(vuln.MatchedAt),
				Severity:    NormalizeSeverity(vuln.Severity),
				Source:      vuln.Source,
				TemplateID:  vuln.TemplateID,
				Title:       vuln.Title,
				Description: vuln.Description,
				Evidence:    vuln.Evidence,
				Tags:        vuln.Tags,
				CVEs:        vuln.CVEs,
				CWEs:        vuln.CWEs,
				References:  vuln.References,
				CVSS:        vuln.CVSS,
				EPSS:        vuln.EPSS,
				KEV:         vuln.KEV,
				MatchedAt:   vuln.MatchedAt,
			}
			f.ID = f.Fingerprint()
			findings = append(findings, f)
		}
	}

	for _, verified := range rep.JSVerified {
		f := Finding{
			Kind:       "verified_secret",
			Asset:      hostOf(verified.URL),
			URL:        verified.URL,
			Severity:   NormalizeSeverity(verified.Severity),
			Source:     "jsverify",
			TemplateID: verified.Pattern,
			Title:      verified.Kind,
			Evidence:   verified.Evidence,
			MatchedAt:  verified.URL,
		}
		if f.Asset == "" {
			f.Asset = hostOf(verified.Page)
		}
		f.ID = f.Fingerprint()
		findings = append(findings, f)
	}

	return findings
}

// urlIfHTTP returns the value when it looks like an http(s) URL, otherwise "".
func urlIfHTTP(value string) string {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	if parsed.Scheme == "http" || parsed.Scheme == "https" {
		return parsed.String()
	}
	return ""
}

// hostOf extracts the hostname from a URL, or "" when it is not a URL.
func hostOf(value string) string {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}
