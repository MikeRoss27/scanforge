package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/ui"
)

// PrintTerminalSummary prints a colorful and clean summary of the scan to stdout
func PrintTerminalSummary(r *Report) {
	label := func(s string) string { return ui.DimBold(s) }

	fmt.Println()
	fmt.Printf("%s\n", ui.Bold(ui.Primary("=== SCAN SUMMARY ===")))
	fmt.Printf("%-8s %s\n", label("Target:"), ui.Bold(r.Target))
	fmt.Printf("%-8s %s\n", label("Profile:"), r.Profile)
	fmt.Printf("%-8s %s\n", label("Status:"), formatStatus(r.Status))
	fmt.Printf("%-8s %s\n", label("Time:"), r.CompletedAt.Sub(r.StartedAt).Round(time.Second))

	var totalPorts, totalPaths, totalVulns int
	var allTechs []string
	vulns := make([]*VulnerabilityWithTarget, 0)

	for assetName, asset := range r.Assets {
		totalPorts += len(asset.Ports)
		totalPaths += len(asset.Paths)
		totalVulns += len(asset.Vulnerabilities)
		allTechs = append(allTechs, asset.Technologies...)

		for _, v := range asset.Vulnerabilities {
			vulns = append(vulns, &VulnerabilityWithTarget{
				Target: assetName,
				Vuln:   v,
			})
		}
	}

	fmt.Printf("\n%s\n", ui.DimBold("--- STATISTICS ---"))
	fmt.Printf("%-8s %s\n", label("Assets:"), ui.Bold(fmt.Sprintf("%d", len(r.Assets))))
	fmt.Printf("%-8s %s\n", label("Ports:"), ui.Bold(fmt.Sprintf("%d", totalPorts)))
	fmt.Printf("%-8s %s\n", label("Paths:"), ui.Bold(fmt.Sprintf("%d", totalPaths)))

	// Top technologies
	if len(allTechs) > 0 {
		techMap := make(map[string]int)
		for _, t := range allTechs {
			techMap[t]++
		}
		var uniqueTechs []string
		for t := range techMap {
			uniqueTechs = append(uniqueTechs, t)
		}
		sort.Strings(uniqueTechs)

		fmt.Printf("%-8s %s\n", label("Tech:"), ui.Secondary(strings.Join(uniqueTechs, ", ")))
	}

	fmt.Printf("\n%s\n", ui.DimBold("--- VULNERABILITIES ---"))
	if len(vulns) == 0 {
		fmt.Printf("%s\n", ui.Green("✓ No vulnerabilities detected!"))
	} else {
		fmt.Printf("Total Findings: %s\n\n", ui.Bold(fmt.Sprintf("%d", len(vulns))))

		// Sort vulnerabilities by severity (Critical > High > Medium > Low > Info)
		sort.Slice(vulns, func(i, j int) bool {
			return severityWeight(vulns[i].Vuln.Severity) > severityWeight(vulns[j].Vuln.Severity)
		})

		fmt.Printf("%-10s | %-30s | %-20s | %s\n", ui.Bold("SEVERITY"), ui.Bold("TARGET"), ui.Bold("TEMPLATE"), ui.Bold("TITLE"))
		fmt.Println(strings.Repeat("-", 100))
		for _, v := range vulns {
			sev := ui.Severity(strings.ToUpper(v.Vuln.Severity))
			// Truncate title if too long
			title := v.Vuln.Title
			if len(title) > 40 {
				title = title[:37] + "..."
			}
			target := v.Target
			if len(target) > 30 {
				target = target[:27] + "..."
			}

			fmt.Printf("%-10s | %-30s | %-20s | %s\n",
				sev,
				target,
				ui.Dim(v.Vuln.TemplateID),
				title,
			)
		}
	}
	fmt.Println()
}

type VulnerabilityWithTarget struct {
	Target string
	Vuln   *Vulnerability
}

func formatStatus(status string) string {
	switch status {
	case "completed":
		return ui.Green("✓ " + status)
	case "partial":
		return ui.Yellow("◐ " + status)
	default:
		return ui.Red("✗ " + status)
	}
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
