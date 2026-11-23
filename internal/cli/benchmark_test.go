package cli

import (
	"strings"
	"testing"
)

func TestBenchmarkListPrintsEveryLab(t *testing.T) {
	output, err := execute(t, "benchmark", "list")
	if err != nil {
		t.Fatalf("benchmark list error = %v", err)
	}
	for _, want := range []string{"firing-range", "testphp-vulnweb", "juice-shop-demo", "dvwa"} {
		if !strings.Contains(output, want) {
			t.Errorf("benchmark list output missing %q:\n%s", want, output)
		}
	}
}

func TestBenchmarkListJSON(t *testing.T) {
	output, err := execute(t, "benchmark", "list", "--json")
	if err != nil {
		t.Fatalf("benchmark list --json error = %v", err)
	}
	for _, want := range []string{`"name": "dvwa"`, `"strict": true`} {
		if !strings.Contains(output, want) {
			t.Errorf("benchmark list --json output missing %q:\n%s", want, output)
		}
	}
}

func TestBenchmarkRunRequiresLabOrAll(t *testing.T) {
	if _, err := execute(t, "benchmark", "run"); err == nil {
		t.Fatal("expected an error when neither a lab nor --all is given")
	}
}

func TestBenchmarkRunRejectsLabWithAll(t *testing.T) {
	if _, err := execute(t, "benchmark", "run", "dvwa", "--all"); err == nil {
		t.Fatal("expected an error when both a lab and --all are given")
	}
}

func TestBenchmarkRunRejectsTargetWithAll(t *testing.T) {
	if _, err := execute(t, "benchmark", "run", "--all", "--target", "http://localhost:1234"); err == nil {
		t.Fatal("expected an error when --target is combined with --all")
	}
}

func TestBenchmarkRunUnknownLab(t *testing.T) {
	if _, err := execute(t, "benchmark", "run", "not-a-real-lab", "--dry-run"); err == nil {
		t.Fatal("expected an error for an unknown lab name")
	}
}

func TestSubcommandHelpIncludesBenchmark(t *testing.T) {
	output, err := execute(t, "benchmark", "--help")
	if err != nil {
		t.Fatalf("benchmark --help error = %v", err)
	}
	if !strings.Contains(output, "NOT part of an authorized client engagement") {
		t.Errorf("benchmark --help should flag itself as a maintainer tool:\n%s", output)
	}
}

func TestRootHelpListsBenchmark(t *testing.T) {
	output, err := execute(t, "--help")
	if err != nil {
		t.Fatalf("--help error = %v", err)
	}
	if !strings.Contains(output, "Benchmark the scan pipeline") {
		t.Errorf("root help missing the benchmark command:\n%s", output)
	}
}
