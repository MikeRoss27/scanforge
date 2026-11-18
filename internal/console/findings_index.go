package console

import (
	"sort"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	"github.com/charmbracelet/x/ansi"
)

// Bounds on what one finding type may print at normal and verbose levels.
// The recap still counts every occurrence, so suppressing a line never
// loses information from the final summary or report.json.
const (
	highOccurrencesNormal  = 1
	highOccurrencesVerbose = 3
	compactValuesNormal    = 10
	compactValuesVerbose   = 25
)

// findingIndex tracks the distinct findings of a run so the console can
// deduplicate the live stream without hiding the actual evidence.
//
// Critical/high finding types are tall blocks: the first occurrence expands
// with its evidence, later occurrences collapse into the recap count.
// Medium/low/info findings are one-line events: one line per distinct
// evidence value (the exposed email, secret, host, ...), identical values
// collapsing into a count. Occurrences suppressed live are never lost:
// they are counted here and summarized in the closing recap.
type findingIndex struct {
	// key is module + "\x00" + normalized title.
	types map[string]*findingStat
}

type findingStat struct {
	module   string
	severity string
	title    string
	count    int

	// valuesSeen deduplicates compact findings on their evidence value:
	// nine different emails produce nine lines, the same email repeated
	// produces one. shownValues enforces the per-type print cap.
	valuesSeen  map[string]bool
	shownValues int
}

func newFindingIndex() *findingIndex {
	return &findingIndex{types: map[string]*findingStat{}}
}

// record registers one occurrence and reports whether the console should
// render it live, and whether it deserves the expanded block.
func (f *findingIndex) record(e orchestrator.FindingEvent, v Verbosity) (show bool, expanded bool) {
	key := strings.ToLower(strings.TrimSpace(e.Module)) + "\x00" +
		strings.ToLower(strings.TrimSpace(singleLine(e.Title)))

	stat, ok := f.types[key]
	if !ok {
		severity := strings.ToUpper(strings.TrimSpace(e.Severity))
		if severity == "" {
			severity = "INFO"
		}
		stat = &findingStat{
			module:   singleLine(e.Module),
			severity: severity,
			title:    singleLine(e.Title),
		}
		f.types[key] = stat
	}
	stat.count++

	if isHighSeverity(stat.severity) {
		// The block is expensive: show it once, a few times at -v, and
		// every occurrence at -vvv. Only the first expands.
		limit := highOccurrencesNormal
		switch {
		case v >= Trace:
			limit = stat.count
		case v >= Verbose:
			limit = highOccurrencesVerbose
		}
		if stat.count > limit {
			return false, false
		}
		return true, stat.count == 1
	}

	// Compact findings are cheap, but a leak can repeat the same value on
	// many lines: print each distinct evidence value once.
	value := strings.TrimSpace(singleLine(e.Detail))
	if value == "" {
		return stat.count == 1, false
	}
	if stat.valuesSeen == nil {
		stat.valuesSeen = map[string]bool{}
	}
	if stat.valuesSeen[value] {
		return false, false
	}
	limit := compactValuesNormal
	switch {
	case v >= Trace:
		limit = stat.count
	case v >= Verbose:
		limit = compactValuesVerbose
	}
	if stat.shownValues >= limit {
		return false, false
	}
	stat.valuesSeen[value] = true
	stat.shownValues++
	return true, false
}

// total returns the number of findings recorded so far.
func (f *findingIndex) total() int {
	total := 0
	for _, stat := range f.types {
		total += stat.count
	}
	return total
}

// bySeverity returns severity counts computed from the live stream, falling
// back to the report numbers when the run produced no findings (e.g. a plan).
func (f *findingIndex) bySeverity() map[string]int {
	counts := map[string]int{}
	for _, stat := range f.types {
		counts[strings.ToLower(stat.severity)] += stat.count
	}
	return counts
}

// distinct returns the distinct finding types ordered by severity
// (critical first), then by occurrence count, then title.
func (f *findingIndex) distinct() []*findingStat {
	stats := make([]*findingStat, 0, len(f.types))
	for _, stat := range f.types {
		stats = append(stats, stat)
	}
	sort.Slice(stats, func(i, j int) bool {
		wi, wj := severityWeightValue(stats[i].severity), severityWeightValue(stats[j].severity)
		if wi != wj {
			return wi > wj
		}
		if stats[i].count != stats[j].count {
			return stats[i].count > stats[j].count
		}
		return stats[i].title < stats[j].title
	})
	return stats
}

func severityWeightValue(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}

// recapRows renders the "finding types" section of the closing summary: one
// row per finding type with its occurrence count. This is how the complete
// story (secrets, emails, internal hosts, ...) survives a noisy scan.
func (r *Renderer) recapRows(limit int) []string {
	stats := r.findings.distinct()
	if len(stats) == 0 {
		return nil
	}
	if limit <= 0 {
		limit = 10
	}

	var rows []string
	for i, stat := range stats {
		if i == limit {
			rows = append(rows, r.th.Dim("  … and "+itoa(len(stats)-i)+" more finding types (see report.json)"))
			break
		}
		rows = append(rows, r.recapRow(stat))
	}
	return rows
}

func (r *Renderer) recapRow(stat *findingStat) string {
	title := stat.title
	if title == "" {
		title = stat.module
	}
	module := ""
	if stat.module != "" {
		module = " (" + stat.module + ")"
	}
	suffix := module + " ×" + itoa(stat.count)
	// Keep the count last, truncating the title if needed so the severity
	// and the occurrence count never disappear past the terminal edge.
	budget := r.ruleWidth() - 2 - 8 - 1 - len([]rune(suffix))
	if budget < 10 {
		budget = 10
	}
	return "  " + r.th.Severity(padSeverity(stat.severity)) + " " +
		ansi.Truncate(title, budget, "…") + r.th.Dim(suffix)
}

func padSeverity(severity string) string {
	if len(severity) >= 8 {
		return severity
	}
	return severity + strings.Repeat(" ", 8-len(severity))
}
