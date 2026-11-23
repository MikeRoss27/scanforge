// Package cli implements the scanforge cobra commands. help.go replaces Cobra's plain-text help template with one shared, colored
// renderer for the whole command tree. Section labels, ordering and wording
// follow Cobra's defaults so scripts, tests and docs keep parsing the output;
// lipgloss adds color only when the terminal supports it — piped output and
// NO_COLOR fall back to plain text automatically.
package cli

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/ui"
	"github.com/spf13/cobra"
)

// annGroupedFlags marks commands whose flag section is rendered by a custom
// grouping function (runFlagHelp) instead of the flat local flag list.
const annGroupedFlags = "cli.grouped-flags"

// minNamePadding mirrors Cobra's minimum width for the command name column
// in the command listings.
const minNamePadding = 11

// flagLineRe splits a pflag usage line into the flag token, the alignment gap
// and the description. pflag pads descriptions with at least three spaces, so
// the gap never swallows the first word of the description.
var flagLineRe = regexp.MustCompile(`^(\s*(?:-[[:alnum:]], )?--[^\s]+(?: [^\s]+)?)(\s{2,})(.*)$`)

// renderColoredHelp renders the help of any command with ScanForge styling.
// Installed on the root command, it is inherited by every child through
// Cobra's HelpFunc lookup.
func renderColoredHelp(cmd *cobra.Command, _ []string) {
	_, _ = fmt.Fprint(cmd.OutOrStdout(), renderHelp(cmd))
}

// renderHelp assembles the help of a single command from its sections. Every
// section builder returns a block that ends with a blank line, except the
// footer, which ends with the final newline.
func renderHelp(cmd *cobra.Command) string {
	var b strings.Builder
	b.WriteString(writeDescription(cmd))
	b.WriteString(writeUsage(cmd))
	b.WriteString(writeAliases(cmd))
	b.WriteString(writeExamples(cmd))
	b.WriteString(writeCommands(cmd))
	b.WriteString(writeFlags(cmd))
	b.WriteString(writeGlobalFlags(cmd))
	b.WriteString(writeFooter(cmd))
	return strings.TrimRight(b.String(), "\n") + "\n"
}

func writeDescription(cmd *cobra.Command) string {
	long := strings.TrimSpace(cmd.Long)
	if long == "" {
		long = strings.TrimSpace(cmd.Short)
	}
	if long == "" {
		return ""
	}
	lines := strings.Split(long, "\n")
	rendered := make([]string, len(lines))
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " ")
		rendered[i] = ui.Text(lines[i])
	}
	return strings.Join(rendered, "\n") + "\n\n"
}

func writeUsage(cmd *cobra.Command) string {
	var lines []string
	if cmd.Runnable() {
		lines = append(lines, cmd.UseLine())
	}
	if cmd.HasAvailableSubCommands() {
		lines = append(lines, cmd.CommandPath()+" [command]")
	}
	if len(lines) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(ui.Title("Usage:"))
	b.WriteString("\n")
	for _, line := range lines {
		if rest, ok := strings.CutPrefix(line, cmd.CommandPath()); ok {
			line = ui.Primary(cmd.CommandPath()) + ui.Dim(rest)
		} else {
			line = ui.Text(line)
		}
		b.WriteString("  ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n") + "\n\n"
}

func writeAliases(cmd *cobra.Command) string {
	if len(cmd.Aliases) == 0 {
		return ""
	}
	return ui.Title("Aliases:") + "\n  " + ui.Primary(strings.Join(append([]string{cmd.Name()}, cmd.Aliases...), ", ")) + "\n\n"
}

func writeExamples(cmd *cobra.Command) string {
	if strings.TrimSpace(cmd.Example) == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString(ui.Title("Examples:"))
	b.WriteString("\n")
	for _, line := range strings.Split(strings.TrimRight(cmd.Example, "\n"), "\n") {
		b.WriteString(ui.Dim(line))
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n") + "\n\n"
}

func writeCommands(cmd *cobra.Command) string {
	if !cmd.HasAvailableSubCommands() {
		return ""
	}
	available := make([]*cobra.Command, 0, len(cmd.Commands()))
	for _, c := range cmd.Commands() {
		if c.IsAvailableCommand() || c.Name() == "help" {
			available = append(available, c)
		}
	}
	pad := minNamePadding
	for _, c := range available {
		if w := len(c.Name()); w > pad {
			pad = w
		}
	}
	label := "Available Commands:"
	if len(cmd.Groups()) > 0 {
		label = "Additional Commands:"
	}
	var blocks []string
	for _, group := range cmd.Groups() {
		entries := commandsInGroup(available, group.ID)
		if len(entries) == 0 {
			continue
		}
		lines := []string{group.Title}
		for _, c := range entries {
			name := fmt.Sprintf("%-*s", pad, c.Name())
			lines = append(lines, "  "+ui.Primary(name)+" "+ui.Secondary(c.Short))
		}
		blocks = append(blocks, strings.Join(lines, "\n")+"\n\n")
	}
	ungrouped := commandsInGroup(available, "")
	if len(ungrouped) > 0 {
		lines := []string{label}
		for _, c := range ungrouped {
			name := fmt.Sprintf("%-*s", pad, c.Name())
			lines = append(lines, "  "+ui.Primary(name)+" "+ui.Secondary(c.Short))
		}
		blocks = append(blocks, strings.Join(lines, "\n")+"\n\n")
	}
	if len(blocks) == 0 {
		return ""
	}
	var b strings.Builder
	for _, block := range blocks {
		b.WriteString(block)
	}
	return b.String()
}

func commandsInGroup(available []*cobra.Command, groupID string) []*cobra.Command {
	var entries []*cobra.Command
	for _, c := range available {
		if c.GroupID == groupID {
			entries = append(entries, c)
		}
	}
	return entries
}

func writeFlags(cmd *cobra.Command) string {
	local := cmd.LocalFlags()
	if !local.HasAvailableFlags() {
		return ""
	}
	var b strings.Builder
	if cmd.Annotations[annGroupedFlags] != "true" {
		b.WriteString(ui.Title("Flags:"))
		b.WriteString("\n")
		b.WriteString(colorizeFlagUsages(local.FlagUsagesWrapped(0)))
		return b.String() + "\n\n"
	}
	return colorizeFlagUsages(runFlagHelp(cmd)) + "\n\n"
}

func writeGlobalFlags(cmd *cobra.Command) string {
	if !cmd.HasParent() {
		return ""
	}
	inherited := cmd.InheritedFlags()
	if !inherited.HasAvailableFlags() {
		return ""
	}
	var b strings.Builder
	b.WriteString(ui.Title("Global Flags:"))
	b.WriteString("\n")
	b.WriteString(colorizeFlagUsages(inherited.FlagUsagesWrapped(0)))
	return b.String() + "\n\n"
}

func writeFooter(cmd *cobra.Command) string {
	if !cmd.HasAvailableSubCommands() {
		return ""
	}
	return "Use " + ui.Secondary(`"`+cmd.CommandPath()+` [command] --help"`) + ui.Dim(" for more information about a command.") + "\n"
}

// colorizeFlagUsages colors one rendered flag block: group headings in the
// accent title color, flag tokens in primary, descriptions in the subtle
// secondary tone. Continuation lines keep the secondary tone.
func colorizeFlagUsages(usage string) string {
	lines := strings.Split(strings.TrimRight(usage, "\n"), "\n")
	for i, line := range lines {
		trimmed := strings.TrimRight(line, " ")
		switch {
		case trimmed == "":
			lines[i] = ""
		case !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":"):
			lines[i] = ui.Title(line)
		case flagLineRe.MatchString(line):
			m := flagLineRe.FindStringSubmatch(line)
			lines[i] = ui.Text(m[1]) + m[2] + ui.Secondary(m[3])
		default:
			lines[i] = ui.Secondary(trimmed)
		}
	}
	return strings.Join(lines, "\n")
}
