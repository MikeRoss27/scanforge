package benchmark

import (
	"testing"
	"time"

	"github.com/MikeRoss27/scanforge/internal/report"
)

func fakeReport(vulns []*report.Vulnerability, technologies []string) *report.Report {
	return &report.Report{
		Assets: map[string]*report.Asset{
			"example.com": {
				Name:            "example.com",
				Technologies:    technologies,
				Vulnerabilities: vulns,
			},
		},
	}
}

func TestScoreReportStrictLabFullyPasses(t *testing.T) {
	lab := Lab{
		Name:   "dvwa",
		Strict: true,
		ExpectedCategories: []CategoryExpectation{
			{Name: "sqli", Keywords: []string{"sqli", "sql-injection"}, MinCount: 1},
			{Name: "xss", Keywords: []string{"xss"}, MinCount: 1},
		},
		ExpectedTechnologies: []string{"php"},
	}
	rep := fakeReport([]*report.Vulnerability{
		{Title: "Blind SQL Injection", Tags: []string{"sqli"}},
		{Title: "Reflected XSS", Tags: []string{"xss"}},
	}, []string{"PHP 7.4"})

	score := ScoreReport(lab, rep, "completed", 5*time.Second)

	if !score.Completed {
		t.Fatal("Completed = false, want true")
	}
	if !score.OverallPass {
		t.Fatalf("OverallPass = false, want true: %+v", score)
	}
	if score.FindingsTotal != 2 {
		t.Fatalf("FindingsTotal = %d, want 2", score.FindingsTotal)
	}
	for _, cat := range score.Categories {
		if !cat.Pass {
			t.Errorf("category %q did not pass: %+v", cat.Name, cat)
		}
	}
	if len(score.Technologies) != 1 || !score.Technologies[0].Found {
		t.Fatalf("Technologies = %+v, want php found", score.Technologies)
	}
}

func TestScoreReportStrictLabMissingCategoryFails(t *testing.T) {
	lab := Lab{
		Name:   "dvwa",
		Strict: true,
		ExpectedCategories: []CategoryExpectation{
			{Name: "sqli", Keywords: []string{"sqli"}, MinCount: 1},
			{Name: "command-injection", Keywords: []string{"command-injection", "rce"}, MinCount: 1},
		},
	}
	rep := fakeReport([]*report.Vulnerability{
		{Title: "Blind SQL Injection", Tags: []string{"sqli"}},
	}, nil)

	score := ScoreReport(lab, rep, "completed", time.Second)

	if score.OverallPass {
		t.Fatalf("OverallPass = true, want false (strict lab missing command-injection): %+v", score)
	}
	var sqli, cmdInjection CategoryResult
	for _, cat := range score.Categories {
		switch cat.Name {
		case "sqli":
			sqli = cat
		case "command-injection":
			cmdInjection = cat
		}
	}
	if !sqli.Pass {
		t.Errorf("sqli should pass: %+v", sqli)
	}
	if cmdInjection.Pass {
		t.Errorf("command-injection should fail: %+v", cmdInjection)
	}
}

func TestScoreReportNonStrictLabMissingCategoryStillPasses(t *testing.T) {
	lab := Lab{
		Name:   "firing-range",
		Strict: false,
		ExpectedCategories: []CategoryExpectation{
			{Name: "xss", Keywords: []string{"xss"}, MinCount: 5},
		},
	}
	rep := fakeReport(nil, nil) // no vulnerabilities at all

	score := ScoreReport(lab, rep, "completed", time.Second)

	if !score.OverallPass {
		t.Fatalf("OverallPass = false, want true: a non-strict lab's category misses must not fail it: %+v", score)
	}
	if len(score.Categories) != 1 || score.Categories[0].Pass {
		t.Fatalf("category result should still be computed and reported as failing, just not gating: %+v", score.Categories)
	}
}

func TestScoreReportIncompleteRunFailsRegardlessOfCategories(t *testing.T) {
	lab := Lab{
		Name:   "firing-range",
		Strict: false, // even non-strict, an incomplete run must fail
		ExpectedCategories: []CategoryExpectation{
			{Name: "xss", Keywords: []string{"xss"}, MinCount: 1},
		},
	}
	rep := fakeReport([]*report.Vulnerability{
		{Title: "Reflected XSS", Tags: []string{"xss"}},
	}, nil)

	for _, status := range []string{"failed", "aborted", ""} {
		score := ScoreReport(lab, rep, status, time.Second)
		if score.Completed {
			t.Errorf("status %q: Completed = true, want false", status)
		}
		if score.OverallPass {
			t.Errorf("status %q: OverallPass = true, want false (run never completed)", status)
		}
	}

	for _, status := range []string{"completed", "partial"} {
		score := ScoreReport(lab, rep, status, time.Second)
		if !score.Completed {
			t.Errorf("status %q: Completed = false, want true", status)
		}
	}
}

func TestScoreReportTechnologyMismatchNeverFailsOverallPass(t *testing.T) {
	lab := Lab{
		Name:                 "testphp-vulnweb",
		Strict:               true, // even strict: tech is advisory-only
		ExpectedTechnologies: []string{"ruby-on-rails"},
	}
	rep := fakeReport(nil, []string{"PHP 5.6", "nginx"})

	score := ScoreReport(lab, rep, "completed", time.Second)

	if !score.OverallPass {
		t.Fatalf("OverallPass = false, want true: a technology mismatch must never gate it: %+v", score)
	}
	if len(score.Technologies) != 1 || score.Technologies[0].Found {
		t.Fatalf("Technologies = %+v, want ruby-on-rails not found", score.Technologies)
	}
}

func TestScoreReportNilReport(t *testing.T) {
	lab := Lab{
		Name:   "firing-range",
		Strict: false,
		ExpectedCategories: []CategoryExpectation{
			{Name: "xss", Keywords: []string{"xss"}, MinCount: 1},
		},
	}
	score := ScoreReport(lab, nil, "completed", time.Second)
	if score.FindingsTotal != 0 {
		t.Fatalf("FindingsTotal = %d, want 0 for a nil report", score.FindingsTotal)
	}
	if !score.Completed {
		t.Fatal("Completed = false, want true (a nil report is still a completed run with nothing in it)")
	}
}

func TestCountMatchingVulnerabilitiesMatchesTitleTemplateAndTags(t *testing.T) {
	vulns := []*report.Vulnerability{
		{Title: "Something with SQLi in the title"},
		{TemplateID: "sql-injection-detect"},
		{Tags: []string{"sqli"}},
		{Title: "Unrelated finding"},
		nil,
	}
	if got := countMatchingVulnerabilities(vulns, []string{"sqli", "sql-injection"}); got != 3 {
		t.Fatalf("countMatchingVulnerabilities() = %d, want 3", got)
	}
}

func TestCountMatchingVulnerabilitiesCaseInsensitive(t *testing.T) {
	vulns := []*report.Vulnerability{{Title: "CROSS-SITE SCRIPTING found"}}
	if got := countMatchingVulnerabilities(vulns, []string{"cross-site scripting"}); got != 1 {
		t.Fatalf("countMatchingVulnerabilities() = %d, want 1 (case-insensitive)", got)
	}
}
