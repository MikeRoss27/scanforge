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

	b.WriteString(fmt.Sprintf("# ScanForge Report: %s\n\n", mdInline(r.Target)))
	b.WriteString(fmt.Sprintf("- **Profile:** %s\n", mdInline(r.Profile)))
	b.WriteString(fmt.Sprintf("- **Status:** %s\n", mdInline(r.Status)))
	b.WriteString(fmt.Sprintf("- **Started:** %s\n", r.StartedAt.Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("- **Completed:** %s\n\n", r.CompletedAt.Format("2006-01-02 15:04:05")))

	// Sort assets
	var assetNames []string
	for k := range r.Assets {
		assetNames = append(assetNames, k)
	}
	sort.Strings(assetNames)

	for _, name := range assetNames {
		asset := r.Assets[name]
		b.WriteString(fmt.Sprintf("## Asset: %s\n\n", mdInline(asset.Name)))

		if len(asset.IPs) > 0 {
			b.WriteString(fmt.Sprintf("**IPs:** %s\n\n", strings.Join(asset.IPs, ", ")))
		}
		if len(asset.CNAMEs) > 0 {
			b.WriteString(fmt.Sprintf("**CNAMEs:** %s\n\n", strings.Join(asset.CNAMEs, ", ")))
		}
		if len(asset.CDN) > 0 {
			b.WriteString(fmt.Sprintf("**CDN:** %s\n\n", strings.Join(asset.CDN, ", ")))
		}
		if len(asset.WAFs) > 0 {
			b.WriteString(fmt.Sprintf("**WAF:** %s\n\n", strings.Join(asset.WAFs, ", ")))
		}

		if len(asset.Technologies) > 0 {
			b.WriteString(fmt.Sprintf("**Technologies:** %s\n\n", strings.Join(asset.Technologies, ", ")))
		}

		if len(asset.Ports) > 0 {
			b.WriteString("### Open Ports\n\n")
			var ports []int
			for p := range asset.Ports {
				ports = append(ports, p)
			}
			sort.Ints(ports)
			for _, p := range ports {
				b.WriteString(fmt.Sprintf("- %d\n", p))
			}
			b.WriteString("\n")
		}

		if len(asset.HTTP) > 0 {
			b.WriteString("### HTTP Services\n\n")
			b.WriteString("| URL | Status | Title | Server |\n")
			b.WriteString("|-----|--------|-------|--------|\n")
			for _, service := range asset.HTTP {
				b.WriteString(fmt.Sprintf("| %s | %d | %s | %s |\n",
					markdownCell(service.URL), service.StatusCode,
					markdownCell(service.Title), markdownCell(service.WebServer)))
			}
			b.WriteString("\n")
		}

		if len(asset.TLS) > 0 {
			b.WriteString("### TLS\n\n")
			b.WriteString("| Port | Version | Cipher | Common Name | Expired |\n")
			b.WriteString("|------|---------|--------|-------------|---------|\n")
			for _, service := range asset.TLS {
				b.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %v |\n",
					service.Port, markdownCell(service.Version), markdownCell(service.Cipher),
					markdownCell(service.CommonName), service.Expired))
			}
			b.WriteString("\n")
		}

		if len(asset.Paths) > 0 {
			b.WriteString("### Discovered Paths\n\n")
			for _, p := range asset.Paths {
				b.WriteString(fmt.Sprintf("- %s\n", mdInline(p)))
			}
			b.WriteString("\n")
		}

		if len(asset.Vulnerabilities) > 0 {
			b.WriteString("### Vulnerabilities\n\n")
			b.WriteString("| Severity | Template | Title | Matched At | Evidence | Priority |\n")
			b.WriteString("|----------|----------|-------|------------|----------|----------|\n")
			for _, v := range asset.Vulnerabilities {
				b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n",
					markdownCell(v.Severity), markdownCell(v.TemplateID), markdownCell(v.Title),
					markdownCell(v.MatchedAt), markdownCell(v.Evidence), markdownCell(priorityHint(v))))
			}
			b.WriteString("\n")
		}
	}

	if len(r.JSVerified) > 0 {
		b.WriteString("## JavaScript PoC Verification (jsverify)\n\n")
		b.WriteString("| Verdict | Severity | Pattern | Page | Evidence |\n")
		b.WriteString("|---------|----------|---------|------|----------|\n")
		for _, v := range r.JSVerified {
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
				markdownCell(v.Verdict), markdownCell(v.Severity), markdownCell(v.Pattern),
				markdownCell(v.Page), markdownCell(v.Evidence)))
		}
		b.WriteString("\n")
	}

	return os.WriteFile(path, []byte(b.String()), 0644)
}

func markdownCell(value string) string {
	return mdInline(value)
}

// priorityHint renders the prioritization hints (CISA KEV, EPSS) of a
// vulnerability as a compact human-readable cell.
func priorityHint(v *Vulnerability) string {
	var parts []string
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
