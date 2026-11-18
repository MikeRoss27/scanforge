package console

import (
	"strings"

	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	"github.com/charmbracelet/x/ansi"
)

// findingLabelWidth is the label column of the expanded finding block. It
// matches the run header and summary so all key/value blocks read as one
// layout language.
const findingLabelWidth = labelWidth

// isHighSeverity reports whether a normalized severity deserves the expanded
// block treatment.
func isHighSeverity(severity string) bool {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return true
	default:
		return false
	}
}

// compactFinding renders a finding on one grep-able line, with the actual
// evidence (the exposed email, secret, host, version, ...). The evidence is
// protected from truncation: when the line is too wide the module suffix is
// dropped first, and the target URL is only added at -v:
//
//	[06:55:24] [FND] INFO Email address exposed  (jssecrets)  deepak@example.com
//
// Critical/high use expandedFinding instead (one expanded block per type).
func (r *Renderer) compactFinding(e orchestrator.FindingEvent) []string {
	severity := strings.ToUpper(strings.TrimSpace(e.Severity))
	if severity == "" {
		severity = "INFO"
	}
	title := singleLine(e.Title)
	if title == "" {
		title = singleLine(e.Module)
	}
	head := r.eventLine(TagFound, r.th.Severity(severity)+" "+r.th.Bold(title))

	module := singleLine(e.Module)
	detail := singleLine(e.Detail)
	target := singleLine(e.Target)

	if detail != "" {
		// The evidence is the point of the line: give it the width first,
		// then add the module only when it still fits. A clipped email is
		// worse than a missing provenance (the recap and report carry it).
		value := "  " + r.th.Subtle(detail)
		withModule := head
		if module != "" {
			withModule += "  " + r.th.Dim("("+module+")")
		}
		withModule += value
		width := r.term.Width
		if width <= 0 {
			width = DefaultWidth
		}
		if ansi.StringWidth(withModule) <= width || module == "" {
			head = withModule
		} else {
			head += value
		}
		// The target URL only fits at -v when there is already evidence on
		// the line; at normal verbosity it would only be truncated.
		if target != "" && r.verbosity >= Verbose {
			head += "  " + r.th.Dim(target)
		}
		return []string{head}
	}

	// No evidence: the target is the only location information available,
	// so it stays, with the module last.
	var extras []string
	if module != "" {
		extras = append(extras, r.th.Dim("("+module+")"))
	}
	if target != "" {
		extras = append(extras, r.th.Dim(target))
	}
	if len(extras) > 0 {
		head += "  " + strings.Join(extras, "  ")
	}
	return []string{head}
}

// expandedFinding renders the structured block for critical/high findings:
//
//	[04:32:48] [FND] HIGH
//
//	── exposed-git-config ─────────────────────────────────────────────
//
//	Target       https://dev.example.com/.git/config
//	Module       nuclei
//	Severity     HIGH
//	Evidence     HTTP 200 · Git configuration exposed
//
//	───────────────────────────────────────────────────────────────────
func (r *Renderer) expandedFinding(severity, title string, e orchestrator.FindingEvent) []string {
	var lines []string
	lines = append(lines, r.eventLine(TagFound, r.th.Severity(severity)+" "+r.th.Bold(title)))
	lines = append(lines, "", r.th.rule(title, r.ruleWidth()))

	for _, field := range []struct{ label, value string }{
		{"Target", singleLine(e.Target)},
		{"Module", singleLine(e.Module)},
	} {
		if field.value == "" {
			continue
		}
		rows := r.fieldRows(field.label, field.value)
		lines = append(lines, rows...)
	}
	lines = append(lines, r.fieldRows("Severity", severity)...)
	if detail := singleLine(e.Detail); detail != "" {
		lines = append(lines, evidenceRows(r.th, detail, r.ruleWidth())...)
	}
	lines = append(lines, r.th.rule("", r.ruleWidth()), "")
	return lines
}

// evidenceRows renders the Evidence row, wrapping long values (URLs, secret
// snippets) inside the terminal width with the value column aligned.
func evidenceRows(th theme, value string, width int) []string {
	available := width - findingLabelWidth
	if available < 20 {
		available = 20
	}
	wrapped := ansi.Hardwrap(strings.TrimSpace(value), available, true)
	rows := strings.Split(wrapped, "\n")
	if len(rows) == 0 {
		rows = []string{strings.TrimSpace(value)}
	}
	out := make([]string, 0, len(rows))
	for i, row := range rows {
		row = strings.TrimRight(row, " ")
		if i == 0 {
			out = append(out, th.Subtle("Evidence")+strings.Repeat(" ", findingLabelWidth-8)+row)
			continue
		}
		out = append(out, strings.Repeat(" ", findingLabelWidth)+row)
	}
	return out
}
