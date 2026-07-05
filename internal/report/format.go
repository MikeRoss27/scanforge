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

	b.WriteString(fmt.Sprintf("# ScanForge Report: %s\n\n", r.Target))
	b.WriteString(fmt.Sprintf("- **Profile:** %s\n", r.Profile))
	b.WriteString(fmt.Sprintf("- **Status:** %s\n", r.Status))
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
		b.WriteString(fmt.Sprintf("## Asset: %s\n\n", asset.Name))

		if len(asset.IPs) > 0 {
			b.WriteString(fmt.Sprintf("**IPs:** %s\n\n", strings.Join(asset.IPs, ", ")))
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

		if len(asset.Paths) > 0 {
			b.WriteString("### Discovered Paths\n\n")
			for _, p := range asset.Paths {
				b.WriteString(fmt.Sprintf("- %s\n", p))
			}
			b.WriteString("\n")
		}

		if len(asset.Vulnerabilities) > 0 {
			b.WriteString("### Vulnerabilities\n\n")
			b.WriteString("| Severity | Template | Title |\n")
			b.WriteString("|----------|----------|-------|\n")
			for _, v := range asset.Vulnerabilities {
				b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", v.Severity, v.TemplateID, v.Title))
			}
			b.WriteString("\n")
		}
	}

	return os.WriteFile(path, []byte(b.String()), 0644)
}
