package console

import (
	"fmt"
	"strings"
	"time"
)

// labelWidth is the key column shared by the run header, the summary and
// the finding blocks so they all read as one layout language.
// "Technologies" defines it.
const labelWidth = 13

// Summary holds the facts of a finished run. Every field is optional: the
// renderer only prints what actually happened, never invented metrics.
type Summary struct {
	Target   string
	Status   string // completed | partial | aborted | failed | created
	Duration time.Duration

	// Module outcomes.
	Modules   int
	Completed int
	Failed    []string
	Skipped   []string

	// Discovered inventory (a zero row is hidden).
	Assets int
	Alive  int
	URLs   int
	Ports  int
	Techs  []string

	// Findings counts by severity plus the total.
	Findings map[string]int
	Total    int

	// Report locations, relative to the workspace.
	ReportJSON string
	ReportMD   string
	RunDir     string

	// TriageHint advertises `scanforge triage` when configured.
	TriageHint bool
}

// severityOrder is the display order of the findings recap.
var severityOrder = []string{"critical", "high", "medium", "low", "info"}

// PrintSummary renders the closing "── SCAN COMPLETE ──" block followed by
// the final tagged event line. It works for completed, partial, aborted and
// failed runs — the status line carries the outcome.
func (r *Renderer) PrintSummary(s Summary) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// The summary is the payoff of the run: it must not be glued to the
	// last module line nor leave a dangling progress line behind.
	r.clearVolatileLocked()
	r.stopTickerLocked()
	r.pendingPhase, r.pendingWave = "", 0

	rows := []string{r.th.rule(scanTitle(s.Status), r.ruleWidth()), ""}
	rows = append(rows, r.summaryRows(s)...)
	r.writeRowsLocked(rows)
	r.printClosingEvent(s)
}

func scanTitle(status string) string {
	switch status {
	case "aborted":
		return "SCAN ABORTED"
	case "failed":
		return "SCAN FAILED"
	case "partial":
		return "SCAN PARTIAL"
	default:
		return "SCAN COMPLETE"
	}
}

func (r *Renderer) summaryRows(s Summary) []string {
	var rows []string
	row := func(label, value string) {
		if value == "" {
			return
		}
		prefix := r.th.DimBold(label) + padLabel(label)
		rows = append(rows, valueRows(prefix, value, r.term.Width)...)
	}

	row("Target", s.Target)
	if s.Modules > 0 || s.Duration > 0 {
		row("Duration", humanDuration(s.Duration))
	}
	row("Status", r.statusLabel(s.Status))
	if s.Modules > 0 {
		row("Modules", fmt.Sprintf("%d/%d completed", s.Completed, s.Modules))
	}

	hasInventory := s.Assets > 0 || s.Alive > 0 || s.URLs > 0 || s.Ports > 0 || len(s.Techs) > 0
	if hasInventory {
		rows = append(rows, "")
	}
	row("Assets", countLabel(s.Assets, "asset"))
	row("Alive", countLabel(s.Alive, "host"))
	row("URLs", countLabel(s.URLs, "URL"))
	row("Ports", countLabel(s.Ports, "port"))
	if len(s.Techs) > 0 {
		row("Technologies", strings.Join(s.Techs, " · "))
	}

	findings := s.Findings
	total := s.Total
	if total == 0 && len(findings) == 0 {
		// No report (aborted before generation): fall back to what the
		// live stream actually saw. When a report exists it stays
		// authoritative — it is normalized and deduplicated, unlike the
		// raw events.
		if live := r.findings.total(); live > 0 {
			findings = r.findings.bySeverity()
			total = live
		}
	}
	if total > 0 || len(findings) > 0 {
		rows = append(rows, "")
		row("Findings", itoa(total))
		for _, severity := range severityOrder {
			n := findings[severity]
			if n == 0 {
				continue
			}
			// Pad the plain name, then colorize: the counts must align
			// even when severity labels carry ANSI sequences.
			name := strings.ToUpper(severity)
			name = name + strings.Repeat(" ", 8-len(name))
			rows = append(rows, fmt.Sprintf("%s %s   %d",
				strings.Repeat(" ", labelWidth),
				r.th.Severity(name), n))
		}
		// The distinct-type recap: secrets, emails, internal hosts, ...
		// Every suppressed duplicate is counted here — the full story.
		if recap := r.recapRows(10); len(recap) > 0 {
			rows = append(rows, "", r.th.DimBold("Finding types"))
			rows = append(rows, recap...)
		}
	}

	if len(s.Failed) > 0 || len(s.Skipped) > 0 {
		rows = append(rows, "")
		if len(s.Failed) > 0 {
			prefix := r.th.DimBold("FAILED") + padLabel("FAILED")
			rows = append(rows, strings.Split(prefix+r.th.Red(wrapList(s.Failed, labelWidth, r.ruleWidth())), "\n")...)
		}
		if len(s.Skipped) > 0 {
			prefix := r.th.DimBold("SKIPPED") + padLabel("SKIPPED")
			rows = append(rows, strings.Split(prefix+r.th.Yellow(wrapList(s.Skipped, labelWidth, r.ruleWidth())), "\n")...)
		}
	}

	if s.ReportJSON != "" || s.ReportMD != "" || s.RunDir != "" {
		rows = append(rows, "", r.th.DimBold("Reports"))
		reportRow := func(label, path string) {
			if path == "" {
				return
			}
			prefix := "  " + r.th.DimBold(fmt.Sprintf("%-8s", label)) + " "
			rows = append(rows, valueRows(prefix, r.th.Dim(path), r.term.Width)...)
		}
		reportRow("JSON", s.ReportJSON)
		reportRow("Markdown", s.ReportMD)
		reportRow("Raw", s.RunDir)
	}

	if s.TriageHint && s.Total > 0 {
		rows = append(rows, "", r.th.Dim("triage this run: scanforge triage "+s.RunDir))
	}
	return rows
}

// padLabel returns the spaces between a summary key and its value; the key
// is rendered bold-dim by the caller and padded to labelWidth columns.
func padLabel(label string) string {
	pad := labelWidth - len([]rune(label))
	if pad < 1 {
		pad = 1
	}
	return strings.Repeat(" ", pad)
}

// statusLabel colors the run status; the word itself stays plain so grep
// and log parsing keep working.
func (r *Renderer) statusLabel(status string) string {
	switch status {
	case "completed":
		return r.th.Green(status)
	case "partial":
		return r.th.Yellow(status)
	case "aborted":
		return r.th.Orange(status)
	case "failed":
		return r.th.Red(status)
	default:
		return r.th.Subtle(status)
	}
}

// printClosingEvent writes the final tagged line of the run.
func (r *Renderer) printClosingEvent(s Summary) {
	took := ""
	if s.Duration > 0 {
		took = " in " + humanDuration(s.Duration)
	}
	var tag, message string
	switch s.Status {
	case "completed":
		tag, message = TagOK, "scan completed"+took
	case "aborted":
		tag, message = TagWarn, "scan aborted by user"+took
	case "failed":
		tag, message = TagError, "scan failed"+took
	default:
		tag, message = TagWarn, "scan finished with errors"+took
	}
	r.writeRowsLocked([]string{r.eventLine(tag, message)})
}

// humanDuration renders a duration for humans: "38s", "4m 38s", "1h 04m".
func humanDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	seconds := int(d.Seconds() + 0.5)
	switch {
	case seconds < 60:
		return fmt.Sprintf("%ds", seconds)
	case seconds < 3600:
		return fmt.Sprintf("%dm %02ds", seconds/60, seconds%60)
	default:
		return fmt.Sprintf("%dh %02dm", seconds/3600, seconds/60%60)
	}
}

// countLabel renders a non-zero inventory count, e.g. "34 assets".
func countLabel(n int, noun string) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("%d %s", n, plural(n, noun))
}

func plural(n int, noun string) string {
	if n == 1 {
		return noun
	}
	if strings.HasSuffix(noun, "s") {
		return noun
	}
	return noun + "s"
}

// wrapList joins items on lines of at most width-indent characters so the
// full row fits the terminal width; continuation lines are prefixed with
// indent (the value column) and total width never exceeds width.
func wrapList(items []string, indent, width int) string {
	budget := width - indent
	if budget < 10 {
		budget = 10
	}
	var lines []string
	current := ""
	for _, item := range items {
		switch {
		case current == "":
			current = item
		case len(current)+len(", ")+len(item) <= budget:
			current += ", " + item
		default:
			lines = append(lines, current)
			current = item
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	prefix := strings.Repeat(" ", indent)
	for i := 1; i < len(lines); i++ {
		lines[i] = prefix + lines[i]
	}
	return strings.Join(lines, ",\n")
}
