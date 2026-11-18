package console

import (
	"bytes"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/orchestrator"
)

func finding(module, severity, title, target string) orchestrator.FindingEvent {
	return orchestrator.FindingEvent{
		Module: module, Severity: severity, Title: title,
		Target: target, Detail: "x",
	}
}

func TestHighFindingExpandsOnlyFirstOccurrence(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Handle(finding("jssecrets", "high", "DOM XSS sink", "https://a.example.com/x.js"))
	r.Handle(finding("jssecrets", "high", "DOM XSS sink", "https://a.example.com/y.js"))
	r.Handle(finding("jssecrets", "high", "DOM XSS sink", "https://a.example.com/z.js"))

	out := buf.String()
	if got := strings.Count(out, "[FND]"); got != 1 {
		t.Errorf("expected exactly one expanded block for the type, got %d:\n%s", got, out)
	}
	if !strings.Contains(out, "https://a.example.com/x.js") {
		t.Errorf("first occurrence target lost: %s", out)
	}
	if strings.Contains(out, "y.js") || strings.Contains(out, "z.js") {
		t.Errorf("duplicate occurrences leaked into the stream: %s", out)
	}
}

func TestLowFindingShowsOncePerType(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	for i := 0; i < 6; i++ {
		r.Handle(finding("jssecrets", "info", "Email address exposed", "https://a.example.com/app.js"))
	}
	out := buf.String()
	if got := strings.Count(out, "[FND]"); got != 1 {
		t.Errorf("expected one compact line for repeated info findings, got %d:\n%s", got, out)
	}
}

func TestDifferentTitlesAreNotDeduplicated(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Handle(finding("jssecrets", "high", "DOM XSS sink", "https://a.example.com/x.js"))
	r.Handle(finding("jssecrets", "high", "Prototype pollution", "https://a.example.com/x.js"))
	r.Handle(finding("nuclei", "high", "exposed-git-config", "https://a.example.com/.git/config"))
	out := buf.String()
	if got := strings.Count(out, "[FND]"); got != 3 {
		t.Errorf("three distinct types should render three times, got %d:\n%s", got, out)
	}
}

func TestSameTitleDifferentModulesBothShown(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Handle(finding("jssecrets", "high", "Same title", "https://a.example.com/x.js"))
	r.Handle(finding("nuclei", "high", "Same title", "https://a.example.com/x.js"))
	if got := strings.Count(buf.String(), "[FND]"); got != 2 {
		t.Errorf("same title from two modules should render twice, got %d", got)
	}
}

func TestVerboseKeepsUpToThreeOccurrencesPerType(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, func(o *Options) { o.Verbosity = Verbose })
	for i := 0; i < 5; i++ {
		r.Handle(finding("jssecrets", "high", "DOM XSS sink", "https://a.example.com/x.js"))
	}
	out := buf.String()
	if got := strings.Count(out, "[FND]"); got != 3 {
		t.Errorf("expected 3 occurrences at -v, got %d:\n%s", got, out)
	}
	// Only the first one expands; later occurrences are compact.
	if got := strings.Count(out, "── DOM XSS sink"); got != 1 {
		t.Errorf("expected one expanded block at -v, got %d:\n%s", got, out)
	}
}

func TestTraceKeepsEveryOccurrence(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, func(o *Options) { o.Verbosity = Trace })
	for i := 0; i < 4; i++ {
		r.Handle(finding("jssecrets", "high", "DOM XSS sink", "https://a.example.com/x.js"))
	}
	if got := strings.Count(buf.String(), "[FND]"); got != 4 {
		t.Errorf("expected all occurrences at -vvv, got %d", got)
	}
}

func TestQuietModeAlsoDeduplicates(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, func(o *Options) { o.Verbosity = Quiet })
	for i := 0; i < 4; i++ {
		r.Handle(finding("jssecrets", "info", "Email address exposed", "https://a.example.com/x.js"))
	}
	r.Handle(finding("jssecrets", "critical", "RCE", "https://a.example.com/x.js"))
	out := buf.String()
	if got := strings.Count(out, "[FND]"); got != 2 {
		t.Errorf("expected deduplicated quiet findings, got %d:\n%s", got, out)
	}
}

func TestRecapCountsAndOrdering(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Handle(finding("jssecrets", "high", "DOM XSS sink", "x"))
	r.Handle(finding("jssecrets", "high", "DOM XSS sink", "x"))
	r.Handle(finding("jssecrets", "high", "DOM XSS sink", "x"))
	r.Handle(finding("jssecrets", "info", "Email address exposed", "x"))
	r.Handle(finding("jssecrets", "low", "Internal host/IP", "x"))
	r.Handle(finding("nuclei", "critical", "RCE", "x"))

	r.PrintSummary(Summary{Target: "t", Status: "completed"})
	out := buf.String()

	if got := r.findings.total(); got != 6 {
		t.Errorf("live total = %d, want 6", got)
	}
	for _, want := range []string{
		"Findings", "6",
		"CRITICAL", "HIGH", "LOW", "INFO",
		"DOM XSS sink", "×3",
		"Email address exposed", "Internal host/IP",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("recap missing %q:\n%s", want, out)
		}
	}
	// The recap orders by severity first: critical before high before info.
	crit := strings.Index(out, "RCE")
	high := strings.Index(out, "DOM XSS sink (jssecrets) ×3")
	low := strings.Index(out, "Internal host/IP (jssecrets)")
	info := strings.Index(out, "Email address exposed (jssecrets)")
	if crit >= high || high >= low || low >= info {
		t.Errorf("recap ordering wrong: crit=%d high=%d low=%d info=%d\n%s", crit, high, low, info, out)
	}
}

func TestRecapCapsLongLists(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	for i := 0; i < 20; i++ {
		r.Handle(finding("jssecrets", "low", "type-"+itoa(i), "x"))
	}
	r.PrintSummary(Summary{Target: "t", Status: "completed"})
	out := buf.String()
	if !strings.Contains(out, "more finding types") {
		t.Errorf("recap should cap long lists:\n%s", out)
	}
	if strings.Count(out, "×1") > 15 {
		t.Errorf("recap printed more than 15 rows:\n%s", out)
	}
}

func TestRecapEmptyWhenNoFindings(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.PrintSummary(Summary{Target: "t", Status: "completed"})
	if out := buf.String(); strings.Contains(out, "×") {
		t.Errorf("recap rendered without findings:\n%s", out)
	}
}

func TestRecapTruncatesLongTitles(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Handle(finding("jssecrets", "high", strings.Repeat("long-title ", 12), "x"))
	r.PrintSummary(Summary{Target: "t", Status: "completed"})
	out := buf.String()
	if !strings.Contains(out, "×1") {
		t.Errorf("occurrence count lost:\n%s", out)
	}
}

func TestReportCountsWinOverLiveCountsInSummary(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	// 3 raw occurrences but the normalized report says 1: the report is the
	// authoritative total, the recap still records the live occurrences.
	for i := 0; i < 3; i++ {
		r.Handle(finding("jssecrets", "info", "Email address exposed", "x"))
	}
	r.PrintSummary(Summary{Target: "t", Status: "completed", Total: 1, Findings: map[string]int{"info": 1}})
	out := buf.String()
	if !strings.Contains(out, "Findings     1") {
		t.Errorf("summary should use the report count (1):\n%s", out)
	}
	if !strings.Contains(out, "Email address exposed (jssecrets) ×3") {
		t.Errorf("recap should keep the live occurrence count:\n%s", out)
	}
}

func TestSummaryFallsBackToLiveCountsWithoutReport(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	for i := 0; i < 3; i++ {
		r.Handle(findingWithValue("jssecrets", "high", "RCE", "x", "payload-"+itoa(i)))
	}
	r.PrintSummary(Summary{Target: "t", Status: "aborted"})
	out := buf.String()
	if !strings.Contains(out, "Findings     3") {
		t.Errorf("summary should fall back to live counts:\n%s", out)
	}
}

func findingWithValue(module, severity, title, target, detail string) orchestrator.FindingEvent {
	return orchestrator.FindingEvent{
		Module: module, Severity: severity, Title: title,
		Target: target, Detail: detail,
	}
}

func TestCompactFindingShowsEvidenceValue(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, func(o *Options) { o.Terminal.Width = 120 })
	r.Handle(findingWithValue("jssecrets", "info", "Email address exposed in JavaScript",
		"https://example.com/app.js", "deepak@example.com"))
	out := buf.String()
	if !strings.Contains(out, "deepak@example.com") {
		t.Errorf("compact line hid the exposed email:\n%s", out)
	}
	if !strings.Contains(out, "[FND] INFO Email address exposed in JavaScript") {
		t.Errorf("compact line lost its title:\n%s", out)
	}
}

func TestDistinctEvidenceValuesEachRenderOnce(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, func(o *Options) { o.Terminal.Width = 120 })
	emails := []string{"a@example.com", "b@example.com", "c@example.com"}
	for _, email := range emails {
		// The same leak can be reported twice by overlapping scans.
		r.Handle(findingWithValue("jssecrets", "info", "Email address exposed", "https://example.com/app.js", email))
		r.Handle(findingWithValue("jssecrets", "info", "Email address exposed", "https://example.com/other.js", email))
	}
	out := buf.String()
	if got := strings.Count(out, "[FND]"); got != len(emails) {
		t.Errorf("expected one line per distinct value (%d), got %d:\n%s", len(emails), got, out)
	}
	for _, email := range emails {
		if !strings.Contains(out, email) {
			t.Errorf("missing exposed value %q:\n%s", email, out)
		}
	}
}

func TestCompactValueCapKeepsSummaryComplete(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	for i := 0; i < 18; i++ {
		r.Handle(findingWithValue("jssecrets", "low", "Internal host/IP referenced",
			"https://example.com/app.js", "10.0.0."+itoa(i)))
	}
	r.PrintSummary(Summary{Target: "t", Status: "completed"})
	out := buf.String()
	if got := strings.Count(out, "[FND]"); got != compactValuesNormal {
		t.Errorf("live lines = %d, want cap %d:\n%s", got, compactValuesNormal, out)
	}
	if !strings.Contains(out, "Internal host/IP referenced (jssecrets) ×18") {
		t.Errorf("recap lost suppressed occurrences:\n%s", out)
	}
}

func TestVerboseRaisesCompactValueCap(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, func(o *Options) { o.Verbosity = Verbose })
	for i := 0; i < 18; i++ {
		r.Handle(findingWithValue("jssecrets", "low", "Internal host/IP referenced", "x", "10.0.0."+itoa(i)))
	}
	if got := strings.Count(buf.String(), "[FND]"); got != 18 {
		t.Errorf("-v should show all 18 distinct values, got %d", got)
	}
}

func TestHighFindingNeverExpandsTwiceEvenWithNewValue(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Handle(findingWithValue("jssecrets", "high", "DOM XSS sink", "https://a/x.js", "a.innerHTML=x"))
	r.Handle(findingWithValue("jssecrets", "high", "DOM XSS sink", "https://a/y.js", "b.innerHTML=y"))
	out := buf.String()
	if got := strings.Count(out, "── DOM XSS sink"); got != 1 {
		t.Errorf("expected one expanded block, got %d:\n%s", got, out)
	}
}

func TestRecapHasSectionHeading(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Handle(finding("jssecrets", "high", "DOM XSS sink", "x"))
	r.PrintSummary(Summary{Target: "t", Status: "completed"})
	if !strings.Contains(buf.String(), "Finding types") {
		t.Errorf("summary recap lacks a heading:\n%s", buf.String())
	}
}

func TestPhaseForJoinsMixedWave(t *testing.T) {
	got := phaseFor([]string{"nmap", "tlsx", "httpx", "screenshot"})
	if want := "PORTS · WEB SURFACE"; got != want {
		t.Errorf("phaseFor(mixed) = %q, want %q", got, want)
	}
	if got := phaseFor([]string{"unknown", "nmap"}); got != "PORTS" {
		t.Errorf("phaseFor ignores unknown modules: got %q", got)
	}
	if got := phaseFor([]string{"unknown"}); got != "" {
		t.Errorf("phaseFor(all unknown) = %q, want empty", got)
	}
}
