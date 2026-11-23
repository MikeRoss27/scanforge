package benchmark

import (
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/report"
)

// CategoryResult is one ExpectedCategories entry scored against a report.
type CategoryResult struct {
	Name     string `json:"name"`
	MinCount int    `json:"min_count"`
	Found    int    `json:"found"`
	Pass     bool   `json:"pass"`
}

// TechResult is one ExpectedTechnologies entry scored against a report.
// Advisory only: it is reported but never gates OverallPass, since a
// target's tech stack can drift without that being a ScanForge regression.
type TechResult struct {
	Want  string `json:"want"`
	Found bool   `json:"found"`
}

// Score is the outcome of running one lab and comparing its report against
// the lab's expectations. Field names are a stable, intentional contract:
// internal/cli/benchmark.go serializes this directly as the --json output
// consumed by CI and by AI agents.
type Score struct {
	Lab           string           `json:"lab"`
	Target        string           `json:"target"`
	RunDir        string           `json:"run_dir"`
	DurationSecs  float64          `json:"duration_seconds"`
	Completed     bool             `json:"completed"`
	OverallPass   bool             `json:"overall_pass"`
	Strict        bool             `json:"strict"`
	FindingsTotal int              `json:"findings_total"`
	Categories    []CategoryResult `json:"categories"`
	Technologies  []TechResult     `json:"technologies"`
	Error         string           `json:"error"`
}

// runCompleted reports whether a run's manifest status represents a run
// that actually executed (as opposed to failing outright or being
// aborted) — the same two statuses the rest of the codebase already
// treats as "the run produced something" (see internal/app/events.go).
func runCompleted(status string) bool {
	return status == "completed" || status == "partial"
}

// ScoreReport compares a lab's expectations against the report its run
// produced. It is a pure function — no I/O — so it is cheap to exercise
// with fabricated reports in tests instead of a live scan.
func ScoreReport(lab Lab, rep *report.Report, runStatus string, duration time.Duration) Score {
	score := Score{
		Lab:          lab.Name,
		Target:       lab.Target,
		DurationSecs: duration.Seconds(),
		Completed:    runCompleted(runStatus),
		Strict:       lab.Strict,
	}

	var vulns []*report.Vulnerability
	var technologies []string
	if rep != nil {
		for _, asset := range rep.Assets {
			if asset == nil {
				continue
			}
			vulns = append(vulns, asset.Vulnerabilities...)
			technologies = append(technologies, asset.Technologies...)
		}
	}
	score.FindingsTotal = len(vulns)

	allCategoriesPass := true
	for _, expectation := range lab.ExpectedCategories {
		found := countMatchingVulnerabilities(vulns, expectation.Keywords)
		minCount := expectation.MinCount
		if minCount <= 0 {
			minCount = 1
		}
		pass := found >= minCount
		if !pass {
			allCategoriesPass = false
		}
		score.Categories = append(score.Categories, CategoryResult{
			Name:     expectation.Name,
			MinCount: minCount,
			Found:    found,
			Pass:     pass,
		})
	}

	for _, want := range lab.ExpectedTechnologies {
		score.Technologies = append(score.Technologies, TechResult{
			Want:  want,
			Found: containsSubstringFold(technologies, want),
		})
	}

	score.OverallPass = score.Completed && (!lab.Strict || allCategoriesPass)
	return score
}

// countMatchingVulnerabilities counts vulnerabilities whose Tags, Title or
// TemplateID contain any of the given keywords, case-insensitively.
func countMatchingVulnerabilities(vulns []*report.Vulnerability, keywords []string) int {
	if len(keywords) == 0 {
		return 0
	}
	lowerKeywords := make([]string, len(keywords))
	for i, kw := range keywords {
		lowerKeywords[i] = strings.ToLower(kw)
	}

	count := 0
	for _, vuln := range vulns {
		if vuln == nil {
			continue
		}
		haystack := strings.ToLower(vuln.Title + " " + vuln.TemplateID + " " + strings.Join(vuln.Tags, " "))
		for _, kw := range lowerKeywords {
			if strings.Contains(haystack, kw) {
				count++
				break
			}
		}
	}
	return count
}

// containsSubstringFold reports whether any value in haystack contains want
// as a case-insensitive substring.
func containsSubstringFold(haystack []string, want string) bool {
	lowerWant := strings.ToLower(want)
	for _, value := range haystack {
		if strings.Contains(strings.ToLower(value), lowerWant) {
			return true
		}
	}
	return false
}
