package console

import (
	"strings"

	"github.com/charmbracelet/x/ansi"
)

// wrapLine breaks a rendered line wider than the terminal into multiple
// rows of at most width cells. Continuation rows are prefixed with indent
// spaces so wrapped log lines stay aligned under their message column.
// Lines that fit are returned unchanged.
func wrapLine(s string, width, indent int) []string {
	if width <= 0 || ansi.StringWidth(s) <= width {
		return []string{s}
	}
	if indent >= width {
		indent = 0
	}
	avail := width - indent
	if avail < 10 {
		avail, indent = width, 0
	}
	rows := strings.Split(ansi.Hardwrap(s, avail, true), "\n")
	out := make([]string, 0, len(rows))
	for i, row := range rows {
		row = strings.TrimRight(row, " ")
		if row == "" {
			continue
		}
		if i > 0 {
			row = strings.Repeat(" ", indent) + row
		}
		out = append(out, row)
	}
	if len(out) == 0 {
		return []string{""}
	}
	return out
}

// valueRows renders a "label + value" row, wrapping the value (URLs,
// paths, evidence) so continuation lines align under the value column.
// Used by the header and summary blocks.
func valueRows(prefix, value string, width int) []string {
	if width <= 0 {
		width = DefaultWidth
	}
	if ansi.StringWidth(prefix+value) <= width {
		return []string{prefix + value}
	}
	prefixWidth := ansi.StringWidth(prefix)
	avail := width - prefixWidth
	if avail < 10 {
		// The label alone consumes (nearly) the line: wrap without indent.
		return wrapLine(prefix+value, width, 0)
	}
	rows := strings.Split(ansi.Hardwrap(value, avail, true), "\n")
	out := make([]string, 0, len(rows))
	for i, row := range rows {
		row = strings.TrimRight(row, " ")
		if row == "" {
			continue
		}
		if i == 0 {
			out = append(out, prefix+row)
			continue
		}
		out = append(out, strings.Repeat(" ", prefixWidth)+row)
	}
	if len(out) == 0 {
		return []string{prefix}
	}
	return out
}

// eventIndent picks the continuation indent for a line: event lines align
// under the message column, indented block rows align under their leading
// column, everything else wraps without indent. The check looks through
// ANSI styling, which colored lines lead with.
func eventIndent(line string) int {
	if strings.HasPrefix(ansi.Strip(line), "[") {
		return tagIndent
	}
	if trimmed := strings.TrimLeft(line, " "); len(trimmed) != len(line) {
		return len(line) - len(trimmed)
	}
	return 0
}
