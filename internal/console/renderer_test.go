package console

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	"github.com/charmbracelet/x/ansi"
)

// fixedClock yields a deterministic stamp for every renderer test.
func fixedClock() time.Time {
	return time.Date(2026, 11, 18, 4, 32, 11, 0, time.Local)
}

// newTestRenderer builds a colorless, non-TTY renderer writing into buf.
func newTestRenderer(t *testing.T, buf *bytes.Buffer, opts func(*Options)) *Renderer {
	t.Helper()
	o := Options{
		Out:      buf,
		Colors:   false,
		Terminal: Terminal{Tty: false, Volatile: false, Width: DefaultWidth},
		Clock:    fixedClock,
	}
	if opts != nil {
		opts(&o)
	}
	return New(o)
}

func TestModuleStartRendersRunLine(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Handle(orchestrator.ModuleStartEvent{Name: "nuclei"})
	line := buf.String()
	if !strings.Contains(line, "[04:32:11] [RUN] nuclei") {
		t.Errorf("unexpected RUN line: %q", line)
	}
}

func TestModuleCompletionRendersSummaryAndDuration(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Handle(orchestrator.ModuleDoneEvent{
		Name: "subfinder", Status: "completed", Dur: 2800 * time.Millisecond,
		Summary: "34 subdomains",
	})
	line := buf.String()
	for _, want := range []string{"[OK ]", "subfinder", "34 subdomains", "2.8s"} {
		if !strings.Contains(line, want) {
			t.Errorf("completion line missing %q: %q", want, line)
		}
	}
}

func TestModuleFailureRendersErrLine(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Handle(orchestrator.ModuleDoneEvent{
		Name: "naabu", Status: "failed", Failed: true, Dur: 3 * time.Second,
		Error: "module \"naabu\" failed: exit code 2",
	})
	line := buf.String()
	if !strings.Contains(line, "[ERR]") || !strings.Contains(line, "naabu") {
		t.Errorf("failure line missing tag or module: %q", line)
	}
	// The actionable block explains why and what to do next.
	for _, want := range []string{"exit code 2", "action", "scan continues", "scanforge doctor"} {
		if !strings.Contains(line, want) {
			t.Errorf("error block missing %q: %q", want, line)
		}
	}
}

func TestSkippedModuleNeverLooksLikeSuccess(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Handle(orchestrator.ModuleDoneEvent{Name: "nmap", Status: "skipped"})
	line := buf.String()
	if strings.Contains(line, "[OK ]") {
		t.Errorf("skipped module rendered as success: %q", line)
	}
	if !strings.Contains(line, "[SKP]") || !strings.Contains(line, "nmap") {
		t.Errorf("skipped line missing tag or module: %q", line)
	}
}

func TestAbortedModuleRendersWarn(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Handle(orchestrator.ModuleDoneEvent{Name: "nuclei", Status: "aborted"})
	if line := buf.String(); !strings.Contains(line, "[WRN]") || !strings.Contains(line, "aborted") {
		t.Errorf("aborted module not rendered as a warning: %q", line)
	}
}

func TestWarningRendersTag(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Handle(orchestrator.WarningEvent{Message: "subfinder returned no subdomains"})
	if line := buf.String(); !strings.Contains(line, "[WRN]") || !strings.Contains(line, "returned no subdomains") {
		t.Errorf("warning not rendered: %q", line)
	}
}

func TestLowSeverityFindingStaysCompact(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Handle(orchestrator.FindingEvent{
		Module: "jssecrets", Severity: "low", Title: "Google API key",
		Target: "https://app.example.com/app.js",
	})
	line := buf.String()
	if strings.Count(line, "\n") != 1 {
		t.Errorf("low finding must stay on one line: %q", line)
	}
	for _, want := range []string{"[FND]", "LOW", "Google API key", "app.example.com", "(jssecrets)"} {
		if !strings.Contains(line, want) {
			t.Errorf("compact finding missing %q: %q", want, line)
		}
	}
}

func TestHighSeverityFindingExpandsIntoBlock(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Handle(orchestrator.FindingEvent{
		Module: "nuclei", Severity: "high", Title: "exposed-git-config",
		Target: "https://dev.example.com/.git/config",
		Detail: "HTTP 200 · Git configuration exposed",
	})
	out := buf.String()
	for _, want := range []string{
		"[FND] HIGH",
		"── exposed-git-config",
		"Target",
		"https://dev.example.com/.git/config",
		"Module",
		"nuclei",
		"Severity",
		"Evidence",
		"HTTP 200 · Git configuration exposed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expanded finding missing %q:\n%s", want, out)
		}
	}
	// The block closes with a full divider.
	if !strings.Contains(out, "\n────") {
		t.Errorf("expanded finding missing closing divider:\n%s", out)
	}
}

func TestCriticalSeverityExpandsToo(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Handle(orchestrator.FindingEvent{
		Module: "techcve", Severity: "critical", Title: "RCE (CVE-2026-1234)",
		Target: "example.com", Detail: "nginx 1.18",
	})
	if out := buf.String(); !strings.Contains(out, "CVE-2026-1234") || !strings.Contains(out, "Severity") {
		t.Errorf("critical finding not expanded: %q", out)
	}
}

func TestFindingWithoutSeverityDefaultsToInfo(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Handle(orchestrator.FindingEvent{Module: "httpcheck", Title: "404 page"})
	if out := buf.String(); !strings.Contains(out, "INFO") {
		t.Errorf("missing severity fallback: %q", out)
	}
}

func TestFindingControlCharactersAreStripped(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Handle(orchestrator.FindingEvent{
		Module: "nuclei", Severity: "medium", Title: "injection\n\r\rsink",
	})
	if out := buf.String(); strings.Contains(out, "\n\r") || strings.Contains(out, "\r\r") {
		t.Errorf("control characters leaked into the log: %q", out)
	}
}

func TestDeadlockRendersWarn(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Handle(orchestrator.DeadlockEvent{Message: "dependencies missing, marking remaining as skipped"})
	if out := buf.String(); !strings.Contains(out, "[WRN]") {
		t.Errorf("deadlock not rendered: %q", out)
	}
}

func TestModuleProgressEventDoesNotPrintALogLine(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Handle(orchestrator.ModuleStartEvent{Name: "nuclei"})
	buf.Reset()
	r.Handle(orchestrator.ModuleProgressEvent{Name: "nuclei", Current: 428, Total: 982, Unit: "templates"})
	// Progress feeds the volatile line, which a non-TTY renderer does not
	// draw; the log itself stays silent.
	if buf.Len() != 0 {
		t.Errorf("progress event printed a log line: %q", buf.String())
	}
}

func TestColorsDoNotBreakEventLineDetection(t *testing.T) {
	// Colored event lines lead with an escape sequence; they must still be
	// treated as single-line events (truncated, never wrapped mid-word).
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, func(o *Options) {
		o.Colors = true
		o.Terminal = Terminal{Width: 60}
	})
	r.Info("scope validated (implicit · configured scope file %q does not allow the target)", "scope.txt")
	out := buf.String()
	if strings.Count(strings.TrimSuffix(out, "\n"), "\n") != 0 {
		t.Fatalf("colored event line wrapped:\n%q", out)
	}
	stripped := strings.TrimSuffix(ansi.Strip(out), "\n")
	if ansi.StringWidth(stripped) > 60 {
		t.Fatalf("colored event line exceeds width: %d cells: %q", ansi.StringWidth(stripped), out)
	}
	if !strings.Contains(out, "…") {
		t.Fatalf("colored event line not truncated with ellipsis: %q", out)
	}
}

func TestNonTTYOutputHasNoANSISequences(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.PrintHeader(RunHeader{Target: "example.com", Profile: "web", Scope: "domain + subdomains", Modules: 14, OutputDir: "runs/example.com/x"})
	r.Handle(orchestrator.WaveStartEvent{Wave: 1, Modules: []string{"subfinder"}})
	r.Handle(orchestrator.ModuleStartEvent{Name: "subfinder"})
	r.Handle(orchestrator.ModuleDoneEvent{Name: "subfinder", Status: "completed", Dur: 2 * time.Second, Summary: "8 subdomains"})
	r.Handle(orchestrator.FindingEvent{Module: "nuclei", Severity: "high", Title: "xss", Target: "https://a.example.com", Detail: "reflected"})
	r.PrintSummary(Summary{Target: "example.com", Status: "completed", Duration: 278 * time.Second, Modules: 3, Completed: 3, Total: 1, Findings: map[string]int{"high": 1}})

	if out := buf.String(); strings.Contains(out, "\x1b[") {
		t.Errorf("ANSI escape leaked into non-TTY output:\n%q", out)
	}
}

func TestNonTTYOutputIsDeterministicLines(t *testing.T) {
	render := func() string {
		var buf bytes.Buffer
		r := newTestRenderer(t, &buf, nil)
		r.Handle(orchestrator.ModuleStartEvent{Name: "httpx"})
		r.Handle(orchestrator.ModuleDoneEvent{Name: "httpx", Status: "completed", Dur: 4100 * time.Millisecond, Summary: "17 alive hosts"})
		r.finish()
		return buf.String()
	}
	first, second := render(), render()
	if first != second {
		t.Errorf("non-TTY output is not deterministic:\nfirst:  %q\nsecond: %q", first, second)
	}
	if strings.Contains(first, "\r\x1b[") {
		t.Errorf("carriage-return animation leaked into non-TTY output: %q", first)
	}
}

func TestQuietModeKeepsFindingsAndErrorsOnly(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, func(o *Options) { o.Verbosity = Quiet })
	r.PrintHeader(RunHeader{Target: "example.com", Profile: "web", Modules: 5, OutputDir: "runs/x"})
	r.Handle(orchestrator.WaveStartEvent{Wave: 1, Modules: []string{"subfinder"}})
	r.Handle(orchestrator.ModuleStartEvent{Name: "subfinder"})
	r.Handle(orchestrator.WarningEvent{Message: "empty input"})
	r.Handle(orchestrator.FindingEvent{Module: "nuclei", Severity: "high", Title: "xss", Target: "https://a.example.com"})
	r.Handle(orchestrator.ModuleDoneEvent{Name: "subfinder", Status: "completed", Summary: "8 subdomains"})
	r.PrintSummary(Summary{Target: "example.com", Status: "completed", Modules: 1, Completed: 1})

	out := buf.String()
	for _, unwanted := range []string{"[RUN]", "[INF]", "── DISCOVERY", "Output      runs/x"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("quiet mode leaked %q:\n%s", unwanted, out)
		}
	}
	for _, wanted := range []string{"[FND]", "xss", "[WRN]", "SCAN COMPLETE", "scan completed"} {
		if !strings.Contains(out, wanted) {
			t.Errorf("quiet mode lost %q:\n%s", wanted, out)
		}
	}
}

func TestVerboseModeAddsWaveNumbers(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, func(o *Options) { o.Verbosity = Verbose })
	r.Handle(orchestrator.WaveStartEvent{Wave: 2, Modules: []string{"dnsx"}})
	r.Handle(orchestrator.ModuleStartEvent{Name: "dnsx"})
	if out := buf.String(); !strings.Contains(out, "RESOLUTION · wave 2") {
		t.Errorf("verbose wave header missing:\n%s", out)
	}
}

func TestNormalModeOmitsWaveNumbers(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Handle(orchestrator.WaveStartEvent{Wave: 2, Modules: []string{"dnsx"}})
	r.Handle(orchestrator.ModuleStartEvent{Name: "dnsx"})
	if out := buf.String(); strings.Contains(out, "wave 2") {
		t.Errorf("wave number leaked at normal verbosity:\n%s", out)
	}
}

func TestDryRunSuppressesLifecycleButKeepsPhases(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, func(o *Options) { o.DryRun = true })
	r.Handle(orchestrator.WaveStartEvent{Wave: 1, Modules: []string{"subfinder"}})
	r.Handle(orchestrator.ModuleStartEvent{Name: "subfinder"})
	r.Debug("$ subfinder -d example.com")
	r.Handle(orchestrator.ModuleDoneEvent{Name: "subfinder", Status: "completed", Summary: "8 subdomains"})
	out := buf.String()
	if strings.Contains(out, "[RUN]") || strings.Contains(out, "[OK ]") {
		t.Errorf("dry run rendered module lifecycle lines:\n%s", out)
	}
	if !strings.Contains(out, "DISCOVERY") || !strings.Contains(out, "$ subfinder") {
		t.Errorf("dry run lost the phase header or its command:\n%s", out)
	}
}

func TestUnknownModulesProduceNoPhaseHeader(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Handle(orchestrator.WaveStartEvent{Wave: 1, Modules: []string{"unknowntool"}})
	r.Handle(orchestrator.ModuleStartEvent{Name: "unknowntool"})
	if out := buf.String(); strings.Contains(out, "──") {
		t.Errorf("unknown module produced a fake phase header:\n%s", out)
	}
}

func TestPhaseHeaderPrintedOncePerPhase(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Handle(orchestrator.WaveStartEvent{Wave: 1, Modules: []string{"subfinder"}})
	r.Handle(orchestrator.ModuleStartEvent{Name: "subfinder"})
	r.Handle(orchestrator.WaveStartEvent{Wave: 2, Modules: []string{"dnsbrute"}})
	r.Handle(orchestrator.ModuleStartEvent{Name: "dnsbrute"})
	r.Handle(orchestrator.WaveStartEvent{Wave: 3, Modules: []string{"dnsx"}})
	r.Handle(orchestrator.ModuleStartEvent{Name: "dnsx"})
	r.Handle(orchestrator.WaveStartEvent{Wave: 4, Modules: []string{"httpx"}})
	r.Handle(orchestrator.ModuleStartEvent{Name: "httpx"})
	if got := strings.Count(buf.String(), "── DISCOVERY"); got != 1 {
		t.Errorf("DISCOVERY header printed %d times, want 1:\n%s", got, buf.String())
	}
	if got := strings.Count(buf.String(), "── WEB SURFACE"); got != 1 {
		t.Errorf("WEB SURFACE header printed %d times, want 1:\n%s", got, buf.String())
	}
}

func TestPhaseHeaderWaitsForFirstVisibleLine(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, func(o *Options) { o.DryRun = true })
	// An analysis-only wave produces no visible line: its header must not
	// dangle before the next wave.
	r.Handle(orchestrator.WaveStartEvent{Wave: 6, Modules: []string{"techcve", "jssecrets"}})
	r.Handle(orchestrator.WaveStartEvent{Wave: 7, Modules: []string{"jsverify", "payloadgen"}})
	if out := buf.String(); strings.Contains(out, "──") {
		t.Errorf("silent waves printed dangling phase headers:\n%s", out)
	}
	r.Debug("$ nuclei -l attack-surface.txt")
	out := buf.String()
	if !strings.Contains(out, "── VULNERABILITY ANALYSIS") || !strings.Contains(out, "$ nuclei") {
		t.Errorf("command lost its phase header:\n%s", out)
	}
}

func TestMixedWaveHeaderListsPhases(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Handle(orchestrator.WaveStartEvent{Wave: 8, Modules: []string{"httpcheck", "nuclei"}})
	r.Handle(orchestrator.ModuleStartEvent{Name: "nuclei"})
	out := buf.String()
	if !strings.Contains(out, "── WEB SURFACE · VULNERABILITY ANALYSIS") {
		t.Errorf("mixed wave header missing:\n%s", out)
	}
	if !strings.Contains(out, "[RUN] nuclei") {
		t.Errorf("module line lost its header:\n%s", out)
	}
}

func TestPendingPhaseDiscardedAtSummary(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, func(o *Options) { o.DryRun = true })
	r.Handle(orchestrator.WaveStartEvent{Wave: 6, Modules: []string{"techcve"}})
	r.PrintSummary(Summary{Target: "t", Status: "completed"})
	if out := buf.String(); strings.Contains(out, "VULNERABILITY ANALYSIS") {
		t.Errorf("pending phase leaked into the summary:\n%s", out)
	}
}

func TestSummaryCompletedRun(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.PrintSummary(Summary{
		Target: "example.com", Status: "completed", Duration: 278 * time.Second,
		Modules: 14, Completed: 14,
		Assets: 34, Alive: 17, URLs: 428, Ports: 6,
		Techs:      []string{"nginx", "React", "Next.js", "Cloudflare"},
		Total:      9,
		Findings:   map[string]int{"critical": 1, "high": 2, "medium": 3, "low": 2, "info": 1},
		ReportJSON: "runs/example.com/x/report.json",
		ReportMD:   "runs/example.com/x/report.md",
		RunDir:     "runs/example.com/x",
	})
	out := buf.String()
	for _, want := range []string{
		"── SCAN COMPLETE",
		"Target", "example.com",
		"Duration", "4m 38s",
		"Status", "completed",
		"Modules", "14/14 completed",
		"Assets", "34 assets",
		"Alive", "17 hosts",
		"URLs", "428 URLs",
		"Technologies", "nginx · React",
		"Findings", "9",
		"CRITICAL   1",
		"HIGH       2",
		"MEDIUM     3",
		"LOW        2",
		"INFO       1",
		"Reports",
		"report.json",
		"report.md",
		"[OK ] scan completed in 4m 38s",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q:\n%s", want, out)
		}
	}
}

func TestSummaryPartialRunSeparatesFailedAndSkipped(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.PrintSummary(Summary{
		Target: "example.com", Status: "partial", Duration: 30 * time.Second,
		Modules: 4, Completed: 2,
		Failed:  []string{"naabu (failed)"},
		Skipped: []string{"nmap (skipped)", "nuclei (aborted)"},
	})
	out := buf.String()
	var failedLine, skippedLine string
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.Contains(line, "FAILED"):
			failedLine = line
		case strings.Contains(line, "SKIPPED"):
			skippedLine = line
		}
	}
	if failedLine == "" || strings.Contains(failedLine, "nmap") {
		t.Errorf("FAILED line mixes non-failures: %q", failedLine)
	}
	if skippedLine == "" || strings.Contains(skippedLine, "naabu") {
		t.Errorf("SKIPPED line misses skipped modules: %q", skippedLine)
	}
	if !strings.Contains(out, "[WRN] scan finished with errors in 30s") {
		t.Errorf("partial run closing line missing:\n%s", out)
	}
}

func TestSummaryAbortedAndFailedTitles(t *testing.T) {
	cases := map[string]string{
		"partial": "SCAN PARTIAL",
		"aborted": "SCAN ABORTED",
		"failed":  "SCAN FAILED",
	}
	for status, title := range cases {
		var buf bytes.Buffer
		r := newTestRenderer(t, &buf, nil)
		r.PrintSummary(Summary{Target: "t", Status: status})
		if out := buf.String(); !strings.Contains(out, title) {
			t.Errorf("status %s missing title %q:\n%s", status, title, out)
		}
	}
}

func TestSummaryWrapsLongModuleLists(t *testing.T) {
	items := make([]string, 0, 17)
	for _, name := range []string{
		"dnsx", "httpx", "naabu", "nmap", "tlsx", "whatweb", "wafw00f", "katana",
		"jssecrets", "jsverify", "attacksurface", "techcve", "httpcheck",
		"payloadgen", "screenshot", "ffuf", "nuclei",
	} {
		items = append(items, name+" (skipped)")
	}
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.PrintSummary(Summary{Target: "t", Status: "partial", Skipped: items})
	for _, line := range strings.Split(buf.String(), "\n") {
		if len([]rune(line)) > 96 {
			t.Errorf("summary line exceeds width budget: %q", line)
		}
	}
	if !strings.Contains(buf.String(), "dnsx") || !strings.Contains(buf.String(), "nuclei") {
		t.Errorf("wrapped list lost modules:\n%s", buf.String())
	}
}

func TestSummaryOmitsEmptySections(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.PrintSummary(Summary{Target: "example.com", Status: "completed"})
	out := buf.String()
	for _, unwanted := range []string{"Assets", "Findings", "Reports", "FAILED"} {
		if strings.Contains(out, unwanted+"\n") || strings.Contains(out, unwanted+" ") {
			t.Errorf("empty section %s still rendered:\n%s", unwanted, out)
		}
	}
}

func TestSummaryTriageHintOnlyWithFindings(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.PrintSummary(Summary{Target: "t", Status: "completed", Total: 3, RunDir: "runs/x", TriageHint: true})
	if out := buf.String(); !strings.Contains(out, "scanforge triage runs/x") {
		t.Errorf("triage hint missing:\n%s", out)
	}

	buf.Reset()
	r.PrintSummary(Summary{Target: "t", Status: "completed", RunDir: "runs/x", TriageHint: true})
	if out := buf.String(); strings.Contains(out, "triage") {
		t.Errorf("triage hint printed without findings:\n%s", out)
	}
}

func TestRunHeaderLayout(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.PrintHeader(RunHeader{
		Target: "example.com", Profile: "web", Scope: "domain + subdomains",
		Modules: 14, OutputDir: "runs/example.com/2026-11-18_04-32-11",
		Headers: []string{"Authorization: Bearer x"},
	})
	out := buf.String()
	for _, want := range []string{
		"Target       example.com",
		"Profile      web",
		"Scope        domain + subdomains",
		"Modules      14",
		"Headers      1 custom",
		"Output       runs/example.com/2026-11-18_04-32-11",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("header missing %q:\n%s", want, out)
		}
	}
}

func TestRunHeaderDryRunSuffix(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.PrintHeader(RunHeader{Target: "example.com", Profile: "web", DryRun: true})
	if out := buf.String(); !strings.Contains(out, "web · dry run") {
		t.Errorf("dry-run mode missing from header:\n%s", out)
	}
}

func TestColorsRespectedWhenEnabled(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, func(o *Options) {
		o.Colors = true
		o.Terminal = Terminal{Width: 100}
	})
	r.Handle(orchestrator.FindingEvent{Module: "nuclei", Severity: "high", Title: "xss"})
	if out := buf.String(); !strings.Contains(out, "\x1b[") {
		t.Errorf("colors enabled but no ANSI emitted: %q", out)
	}
}

func TestColorsForcedOffByNOColorStyleRules(t *testing.T) {
	// The theme itself must degrade to plain text when disabled — this is
	// what keeps piped output clean even on color-forcing terminals.
	th := theme{enabled: false, truecolor: true}
	if got := th.Red("x"); got != "x" {
		t.Errorf("disabled theme still colors: %q", got)
	}
	if got := th.Dim("y"); got != "y" {
		t.Errorf("disabled theme still dims: %q", got)
	}
}

func TestTrueColorFallsBackToANSI256(t *testing.T) {
	tc := theme{enabled: true, truecolor: true}
	a256 := theme{enabled: true, truecolor: false}
	if tc.Green("ok") == a256.Green("ok") {
		t.Error("truecolor and ANSI 256 renders are identical; fallback is broken")
	}
	if !strings.Contains(a256.Green("ok"), "38;5;") {
		t.Errorf("ANSI 256 code missing: %q", a256.Green("ok"))
	}
	if !strings.Contains(tc.Green("ok"), "38;2;") {
		t.Errorf("truecolor code missing: %q", tc.Green("ok"))
	}
}

func TestLinesStayInsideNarrowTerminals(t *testing.T) {
	for _, width := range []int{40, 60, 80, 100, 120, 160} {
		var buf bytes.Buffer
		r := newTestRenderer(t, &buf, func(o *Options) {
			o.Terminal = Terminal{Width: width}
		})
		r.PrintHeader(RunHeader{
			Target: "very-long-subdomain-name.example.com", Profile: "web",
			Scope:   "https://scope.example.com/scope.txt · 12 entries",
			Modules: 14, OutputDir: "runs/very-long-subdomain-name.example.com/2026-11-18_04-32-11",
		})
		r.Handle(orchestrator.FindingEvent{
			Module: "nuclei", Severity: "high", Title: "exposed-git-config",
			Target: "https://dev.example.com/.git/config?very=long&query=string&that=wraps",
			Detail: strings.Repeat("evidence ", 12),
		})
		r.Handle(orchestrator.ModuleDoneEvent{Name: "subfinder", Status: "completed", Dur: 2 * time.Second, Summary: "34 subdomains"})
		r.PrintSummary(Summary{Target: "very-long-subdomain-name.example.com", Status: "completed", Modules: 2, Completed: 2})

		for _, line := range strings.Split(buf.String(), "\n") {
			// The divider rules are the only lines the renderer sizes
			// deliberately; everything else must fit within width + slack.
			if len([]rune(line)) > width+2 {
				t.Errorf("width %d: line overflows by %d: %q", width, len([]rune(line))-width, line)
			}
		}
	}
}

func TestRuleWidthNeverExceedsTerminal(t *testing.T) {
	for _, width := range []int{20, 40, 60, 80, 200} {
		var buf bytes.Buffer
		r := newTestRenderer(t, &buf, func(o *Options) {
			o.Terminal = Terminal{Width: width}
		})
		r.Handle(orchestrator.WaveStartEvent{Wave: 1, Modules: []string{"subfinder"}})
		r.Handle(orchestrator.ModuleStartEvent{Name: "subfinder"})
		for _, line := range strings.Split(buf.String(), "\n") {
			if strings.HasPrefix(line, "──") && len([]rune(line)) > width {
				t.Errorf("width %d: rule is %d columns: %q", width, len([]rune(line)), line)
			}
		}
	}
}

func TestFormatDuration(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, ""},
		{-time.Second, ""},
		{2800 * time.Millisecond, "2.8s"},
		{138 * time.Second, "02:18"},
		{2*time.Hour + 3*time.Minute + 4*time.Second, "2:03:04"},
	}
	for _, tc := range cases {
		if got := formatDuration(tc.d); got != tc.want {
			t.Errorf("formatDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestParseVerbosity(t *testing.T) {
	cases := []struct {
		count int
		quiet bool
		want  Verbosity
	}{
		{0, false, Normal},
		{1, false, Verbose},
		{2, false, Debug},
		{3, false, Trace},
		{9, false, Trace},
		{0, true, Quiet},
		{-2, false, Normal},
	}
	for _, tc := range cases {
		if got := ParseVerbosity(tc.count, tc.quiet); got != tc.want {
			t.Errorf("ParseVerbosity(%d, %v) = %v, want %v", tc.count, tc.quiet, got, tc.want)
		}
	}
}

func TestConsumeRendersEventsUntilChannelCloses(t *testing.T) {
	events := []orchestrator.Event{
		orchestrator.WaveStartEvent{Wave: 1, Modules: []string{"subfinder"}},
		orchestrator.ModuleStartEvent{Name: "subfinder"},
		orchestrator.ModuleDoneEvent{Name: "subfinder", Status: "completed", Summary: "8 subdomains"},
	}
	ch := make(chan orchestrator.Event, len(events))
	for _, ev := range events {
		ch <- ev
	}
	close(ch)

	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Consume(ch)
	out := buf.String()
	last := 0
	for _, text := range []string{"DISCOVERY", "[RUN] subfinder", "[OK ] subfinder"} {
		i := strings.Index(out, text)
		if i < last {
			t.Fatalf("%q missing or out of order in:\n%s", text, out)
		}
		last = i
	}
}

func TestProgressTrackerView(t *testing.T) {
	p := newProgressTracker(SpinnerForge)
	now := fixedClock()
	p.start("nuclei", now)
	view := p.view(now.Add(84*time.Second), 80, newTheme(false))
	if !strings.Contains(view, "nuclei") || !strings.Contains(view, "01:24") {
		t.Errorf("progress view missing module or elapsed: %q", view)
	}
	if strings.Contains(view, "\n") {
		t.Errorf("progress view must be a single line: %q", view)
	}

	p.update(orchestrator.ModuleProgressEvent{Name: "nuclei", Current: 428, Total: 982, Unit: "templates"}, now)
	view = p.view(now.Add(84*time.Second), 80, newTheme(false))
	if !strings.Contains(view, "428/982 templates") {
		t.Errorf("progress counts missing: %q", view)
	}

	p.finish("nuclei")
	if p.running() {
		t.Error("tracker still running after the module finished")
	}
	if view := p.view(now, 80, newTheme(false)); view != "" {
		t.Errorf("empty tracker rendered a line: %q", view)
	}
}

func TestProgressTrackerMultipleModules(t *testing.T) {
	p := newProgressTracker(SpinnerForge)
	now := fixedClock()
	p.start("katana", now)
	p.start("nuclei", now)
	view := p.view(now.Add(10*time.Second), 80, newTheme(false))
	if !strings.Contains(view, "katana · nuclei") {
		t.Errorf("concurrent modules not joined on the volatile line: %q", view)
	}
}

func TestProgressTrackerClampsCounts(t *testing.T) {
	p := newProgressTracker(SpinnerForge)
	now := fixedClock()
	p.start("screenshot", now)
	p.update(orchestrator.ModuleProgressEvent{Name: "screenshot", Current: 99, Total: 17, Unit: "pages"}, now)
	if view := p.view(now, 80, newTheme(false)); !strings.Contains(view, "17/17 pages") {
		t.Errorf("progress not clamped to total: %q", view)
	}
}

func TestProgressTrackerTruncatesToWidth(t *testing.T) {
	p := newProgressTracker(SpinnerForge)
	now := fixedClock()
	name := strings.Repeat("m", 100)
	p.start(name, now)
	if view := p.view(now, 40, newTheme(false)); ansiWidth(view) > 39 {
		t.Errorf("volatile line exceeds the terminal width: %q", view)
	}
}

func TestProgressEventFeedsVolatileLineOnTTY(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, func(o *Options) {
		o.Terminal = Terminal{Tty: true, Volatile: true, Width: 80}
	})
	r.Handle(orchestrator.ModuleStartEvent{Name: "nuclei"})
	r.Handle(orchestrator.ModuleProgressEvent{Name: "nuclei", Current: 10, Total: 20, Unit: "hosts"})
	if out := buf.String(); !strings.Contains(out, "\r\x1b[2K") || !strings.Contains(out, "10/20 hosts") {
		t.Errorf("volatile progress line not drawn on TTY: %q", buf.String())
	}

	// A module completion must finalize the volatile line and print the
	// event after it, never on top of it.
	buf.Reset()
	r.Handle(orchestrator.ModuleDoneEvent{Name: "nuclei", Status: "completed", Summary: "5 findings"})
	out := buf.String()
	if !strings.HasPrefix(out, "\r\x1b[2K") {
		t.Errorf("event did not clear the volatile line first: %q", out)
	}
	if strings.Contains(out, "hosts[") || strings.Contains(out, " 10/20") {
		t.Errorf("event glued to the volatile line: %q", out)
	}
	if !strings.Contains(out, "[OK ] nuclei") {
		t.Errorf("completion line lost after volatile clear: %q", out)
	}
}

func TestVolatileLineDisabledOutsideTTY(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil) // non-TTY
	r.Handle(orchestrator.ModuleStartEvent{Name: "nuclei"})
	if out := buf.String(); strings.Contains(out, "\r") {
		t.Errorf("carriage-return output outside a terminal: %q", out)
	}
}

func TestVolatileLineDisabledInDryRun(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, func(o *Options) {
		o.Terminal = Terminal{Tty: true, Volatile: true, Width: 80}
		o.DryRun = true
	})
	r.Handle(orchestrator.ModuleStartEvent{Name: "subfinder"})
	if out := buf.String(); strings.Contains(out, "\r\x1b[2K") {
		t.Errorf("volatile line drawn during a dry run: %q", out)
	}
}

func TestVolatileLineDisabledInQuietMode(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, func(o *Options) {
		o.Terminal = Terminal{Tty: true, Volatile: true, Width: 80}
		o.Verbosity = Quiet
	})
	r.Handle(orchestrator.ModuleStartEvent{Name: "subfinder"})
	if out := buf.String(); strings.Contains(out, "\r\x1b[2K") {
		t.Errorf("volatile line drawn in quiet mode: %q", out)
	}
}

func TestBannerRendering(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.PrintBanner("ScanForge", "v1 · framework")
	out := buf.String()
	if !strings.Contains(out, "ScanForge") || !strings.Contains(out, "v1 · framework") {
		t.Errorf("banner text lost: %q", out)
	}
	if !strings.HasSuffix(strings.TrimRight(out, "\n"), "v1 · framework") {
		t.Errorf("tagline not last: %q", out)
	}
}

func TestWrapListWrapsAtWidth(t *testing.T) {
	long := strings.Repeat("a", 21) + " (skipped)"
	wrapped := wrapList([]string{long, long}, 12, 60)
	lines := strings.Split(wrapped, "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 wrapped lines, got %d: %q", len(lines), wrapped)
	}
	if !strings.HasPrefix(lines[1], strings.Repeat(" ", 12)) {
		t.Errorf("continuation line missing the value-column indent: %q", lines[1])
	}
	for _, line := range lines {
		if len([]rune(line)) > 60 {
			t.Errorf("wrapped list line exceeds width: %q", line)
		}
	}
	if got := wrapList([]string{"naabu (failed)"}, 12, 60); got != "naabu (failed)" {
		t.Errorf("single short item must not be altered, got %q", got)
	}
}

func TestTimestampsUseInjectedClock(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Info("hello")
	if out := buf.String(); !strings.HasPrefix(out, "[04:32:11] [INF] hello") {
		t.Errorf("injected clock not used: %q", out)
	}
}

func TestInfoWarnErrorHelpers(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, nil)
	r.Info("generating report")
	r.Warn("webhook failed: %v", fmt.Errorf("timeout"))
	r.Error("no scope")
	out := buf.String()
	for _, want := range []string{"[INF] generating report", "[WRN] webhook failed: timeout", "[ERR] no scope"} {
		if !strings.Contains(out, want) {
			t.Errorf("helper output missing %q:\n%s", want, out)
		}
	}
}

// ansiWidth measures display width, ignoring ANSI sequences.
func ansiWidth(s string) int {
	return len([]rune(s)) // test strings are plain ASCII
}

// The loading sprite must stay compact and never redraw the large banner.
func TestForgeLoadingStaysCompact(t *testing.T) {
	for _, width := range []int{40, 50, 80, 120} {
		var buf bytes.Buffer
		r := newTestRenderer(t, &buf, func(o *Options) {
			o.Terminal = Terminal{Tty: true, Volatile: true, Width: width}
			o.Spinner = SpinnerForge
		})
		r.Handle(orchestrator.ModuleStartEvent{Name: "nuclei"})
		buf.Reset()
		r.Handle(orchestrator.ModuleProgressEvent{Name: "nuclei", Current: 17, Total: 20, Unit: "pages"})
		wantRows := 0
		if width >= 50 {
			wantRows = forgeRows - 1
		}
		if got := strings.Count(buf.String(), "\n"); got != wantRows {
			t.Fatalf("loading at %d columns drew %d additional rows, want %d", width, got, wantRows)
		}
		if r.volatileRows != wantRows {
			t.Fatalf("tracked %d rows, want %d", r.volatileRows, wantRows)
		}
		if !strings.Contains(buf.String(), "17/20 pages") {
			t.Fatal("loading lost real progress")
		}
		r.Handle(orchestrator.ModuleDoneEvent{Name: "nuclei", Status: "completed"})
		if r.volatile || r.volatileRows != 0 {
			t.Fatal("completed module left a loading line")
		}
	}
}
