package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/ui"
)

type VulnerabilityWithTarget struct {
	Target string
	Vuln   *Vulnerability
}

// maxFindings caps how many findings are rendered in the terminal table so
// the summary stays compact on noisy scans; a trailing row announces the rest.
const maxFindings = 10

// FormatFindingsTable renders a severity-sorted table of findings, or an
// empty string when the report contains none. It is meant to be printed
// below the scan summary box.
func FormatFindingsTable(r *Report) string {
	if r == nil {
		return ""
	}

	vulns := make([]*VulnerabilityWithTarget, 0)
	for assetName, asset := range r.Assets {
		for _, v := range asset.Vulnerabilities {
			vulns = append(vulns, &VulnerabilityWithTarget{Target: assetName, Vuln: v})
		}
	}
	if len(vulns) == 0 {
		return ""
	}

	// Sort vulnerabilities by severity (Critical > High > Medium > Low > Info)
	sort.Slice(vulns, func(i, j int) bool {
		return severityWeight(vulns[i].Vuln.Severity) > severityWeight(vulns[j].Vuln.Severity)
	})

	rows := make([][]string, 0, min(len(vulns), maxFindings+1))
	for i, v := range vulns {
		if i == maxFindings {
			rows = append(rows, []string{
				ui.Dim("…"),
				"",
				"",
				ui.Dim(fmt.Sprintf("and %d more", len(vulns)-i)),
			})
			break
		}
		rows = append(rows, []string{
			ui.Severity(strings.ToUpper(v.Vuln.Severity)),
			truncate(v.Target, 32),
			ui.Dim(truncate(v.Vuln.TemplateID, 24)),
			truncate(v.Vuln.Title, 52),
		})
	}

	return ui.Table([]string{"SEVERITY", "TARGET", "TEMPLATE", "TITLE"}, rows)
}

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n-3]) + "..."
}

func severityWeight(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}
