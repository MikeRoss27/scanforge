package report

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// ANSI Color Codes
const (
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	Gray    = "\033[90m"
	Bold    = "\033[1m"
)

// PrintTerminalSummary prints a colorful and clean summary of the scan to stdout
func PrintTerminalSummary(r *Report) {
	fmt.Println()
	fmt.Printf("%s%s=== SCAN SUMMARY ===%s\n", Bold, Cyan, Reset)
	fmt.Printf("Target:  %s%s%s\n", Bold, r.Target, Reset)
	fmt.Printf("Profile: %s\n", r.Profile)
	fmt.Printf("Status:  %s\n", formatStatus(r.Status))
	fmt.Printf("Time:    %s\n", r.CompletedAt.Sub(r.StartedAt).Round(time.Second))

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

	fmt.Printf("\n%s--- STATISTICS ---%s\n", Bold, Reset)
	fmt.Printf("Assets Found:      %s%d%s\n", Bold, len(r.Assets), Reset)
	fmt.Printf("Open Ports:        %s%d%s\n", Bold, totalPorts, Reset)
	fmt.Printf("Paths Discovered:  %s%d%s\n", Bold, totalPaths, Reset)

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
		
		fmt.Printf("Technologies:      %s%s%s\n", Magenta, strings.Join(uniqueTechs, ", "), Reset)
	}

	fmt.Printf("\n%s--- VULNERABILITIES ---%s\n", Bold, Reset)
	if len(vulns) == 0 {
		fmt.Printf("%s✅ No vulnerabilities detected!%s\n", Green, Reset)
	} else {
		fmt.Printf("Total Findings: %s%d%s\n\n", Bold, len(vulns), Reset)
		
		// Sort vulnerabilities by severity (Critical > High > Medium > Low > Info)
		sort.Slice(vulns, func(i, j int) bool {
			return severityWeight(vulns[i].Vuln.Severity) > severityWeight(vulns[j].Vuln.Severity)
		})

		fmt.Printf("%-10s | %-30s | %-20s | %s\n", "SEVERITY", "TARGET", "TEMPLATE", "TITLE")
		fmt.Println(strings.Repeat("-", 100))
		for _, v := range vulns {
			sevColor := severityColor(v.Vuln.Severity)
			// Truncate title if too long
			title := v.Vuln.Title
			if len(title) > 40 {
				title = title[:37] + "..."
			}
			target := v.Target
			if len(target) > 30 {
				target = target[:27] + "..."
			}
			
			fmt.Printf("%s%-10s%s | %-30s | %s%-20s%s | %s\n", 
				sevColor, strings.ToUpper(v.Vuln.Severity), Reset,
				target,
				Gray, v.Vuln.TemplateID, Reset,
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
	if status == "completed" {
		return fmt.Sprintf("%s%s%s", Green, status, Reset)
	}
	return fmt.Sprintf("%s%s%s", Red, status, Reset)
}

func severityWeight(sev string) int {
	switch strings.ToLower(sev) {
	case "critical": return 5
	case "high": return 4
	case "medium": return 3
	case "low": return 2
	case "info": return 1
	default: return 0
	}
}

func severityColor(sev string) string {
	switch strings.ToLower(sev) {
	case "critical": return Red + Bold
	case "high": return Red
	case "medium": return Yellow
	case "low": return Cyan
	case "info": return Gray
	default: return Reset
	}
}
