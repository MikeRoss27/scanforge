package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// WriteJSON writes the report in JSON format
func (r *Report) WriteJSON(path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// WriteMarkdown writes the report in Markdown format
func (r *Report) WriteMarkdown(path string) error {
	var b strings.Builder

	_, _ = fmt.Fprintf(&b, "# ScanForge Report: %s\n\n", mdInline(r.Target))
	_, _ = fmt.Fprintf(&b, "- **Profile:** %s\n", mdInline(r.Profile))
	_, _ = fmt.Fprintf(&b, "- **Status:** %s\n", mdInline(r.Status))
	_, _ = fmt.Fprintf(&b, "- **Started:** %s\n", r.StartedAt.Format("2006-01-02 15:04:05"))
	_, _ = fmt.Fprintf(&b, "- **Completed:** %s\n\n", r.CompletedAt.Format("2006-01-02 15:04:05"))

	// Sort assets
	var assetNames []string
	for k := range r.Assets {
		assetNames = append(assetNames, k)
	}
	sort.Strings(assetNames)

	for _, name := range assetNames {
		asset := r.Assets[name]
		_, _ = fmt.Fprintf(&b, "## Asset: %s\n\n", mdInline(asset.Name))

		if len(asset.IPs) > 0 {
			_, _ = fmt.Fprintf(&b, "**IPs:** %s\n\n", strings.Join(asset.IPs, ", "))
		}
		if len(asset.CNAMEs) > 0 {
			_, _ = fmt.Fprintf(&b, "**CNAMEs:** %s\n\n", strings.Join(asset.CNAMEs, ", "))
		}
		if len(asset.CDN) > 0 {
			_, _ = fmt.Fprintf(&b, "**CDN:** %s\n\n", strings.Join(asset.CDN, ", "))
		}
		if len(asset.WAFs) > 0 {
			_, _ = fmt.Fprintf(&b, "**WAF:** %s\n\n", strings.Join(asset.WAFs, ", "))
		}

		if len(asset.Technologies) > 0 {
			_, _ = fmt.Fprintf(&b, "**Technologies:** %s\n\n", strings.Join(asset.Technologies, ", "))
		}

		if len(asset.Ports) > 0 {
			b.WriteString("### Open Ports\n\n")
			var ports []int
			for p := range asset.Ports {
				ports = append(ports, p)
			}
			sort.Ints(ports)
			for _, p := range ports {
				_, _ = fmt.Fprintf(&b, "- %d\n", p)
			}
			b.WriteString("\n")
		}

		if len(asset.HTTP) > 0 {
			b.WriteString("### HTTP Services\n\n")
			b.WriteString("| URL | Status | Title | Server |\n")
			b.WriteString("|-----|--------|-------|--------|\n")
			for _, service := range asset.HTTP {
				_, _ = fmt.Fprintf(&b, "| %s | %d | %s | %s |\n",
					markdownCell(service.URL), service.StatusCode,
					markdownCell(service.Title), markdownCell(service.WebServer))
			}
			b.WriteString("\n")
		}

		if len(asset.TLS) > 0 {
			b.WriteString("### TLS\n\n")
			b.WriteString("| Port | Version | Cipher | Common Name | Expired |\n")
			b.WriteString("|------|---------|--------|-------------|---------|\n")
			for _, service := range asset.TLS {
				_, _ = fmt.Fprintf(&b, "| %d | %s | %s | %s | %v |\n",
					service.Port, markdownCell(service.Version), markdownCell(service.Cipher),
					markdownCell(service.CommonName), service.Expired)
			}
			b.WriteString("\n")
		}

		if len(asset.Paths) > 0 {
			b.WriteString("### Discovered Paths\n\n")
			for _, p := range asset.Paths {
				_, _ = fmt.Fprintf(&b, "- %s\n", mdInline(p))
			}
			b.WriteString("\n")
		}

		if len(asset.Vulnerabilities) > 0 {
			b.WriteString("### Vulnerabilities\n\n")
			b.WriteString("| Severity | Template | Title | Matched At | Evidence | Priority |\n")
			b.WriteString("|----------|----------|-------|------------|----------|----------|\n")
			for _, v := range asset.Vulnerabilities {
				_, _ = fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n",
					markdownCell(v.Severity), markdownCell(v.TemplateID), markdownCell(v.Title),
					markdownCell(v.MatchedAt), markdownCell(v.Evidence), markdownCell(priorityHint(v)))
			}
			b.WriteString("\n")
		}
	}

	if len(r.JSVerified) > 0 {
		b.WriteString("## JavaScript PoC Verification (jsverify)\n\n")
		b.WriteString("| Verdict | Severity | Pattern | Page | Evidence |\n")
		b.WriteString("|---------|----------|---------|------|----------|\n")
		for _, v := range r.JSVerified {
			_, _ = fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
				markdownCell(v.Verdict), markdownCell(v.Severity), markdownCell(v.Pattern),
				markdownCell(v.Page), markdownCell(v.Evidence))
		}
		b.WriteString("\n")
	}

	if len(r.Screenshots) > 0 {
		b.WriteString("## Screenshots\n\n")
		for _, shot := range r.Screenshots {
			_, _ = fmt.Fprintf(&b, "- %s\n", mdInline(shot))
		}
		b.WriteString("\n")
	}

	return os.WriteFile(path, []byte(b.String()), 0644)
}

func markdownCell(value string) string {
	return mdInline(value)
}

// priorityHint renders the prioritization hints (CVSS, CISA KEV, EPSS) of a
// vulnerability as a compact human-readable cell.
func priorityHint(v *Vulnerability) string {
	var parts []string
	if v.CVSS > 0 {
		parts = append(parts, fmt.Sprintf("CVSS %.1f", v.CVSS))
	}
	if v.KEV {
		parts = append(parts, "KEV")
	}
	if v.EPSS > 0 {
		parts = append(parts, fmt.Sprintf("EPSS %.2f", v.EPSS))
	}
	return strings.Join(parts, ", ")
}

// mdInline neutralizes Markdown/HTML metacharacters in user-supplied strings
// (targets, titles, evidence) so the report cannot be corrupted or inject
// HTML. "&" must be escaped first: otherwise a value already carrying the
// entity "&lt;img onerror=...&gt;" would round-trip into a live tag in
// renderers that honor raw HTML. Pipes and newlines are handled for table
// cells; Backticks, "<" and the emphasis chars are escaped so raw HTML/JS
// cannot pass through.
func mdInline(value string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"\\", "\\\\",
		"`", "\\`",
		"*", "\\*",
		"_", "\\_",
		"[", "\\[",
		"]", "\\]",
		"<", "&lt;",
		"|", "\\|",
	)
	value = replacer.Replace(value)
	return strings.ReplaceAll(value, "\n", " ")
}
