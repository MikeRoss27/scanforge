package runner

import (
	"os"
	"strings"
)

// AppendCommandLog records the command line of every executed step. The file
// holds full command lines including auth headers (Cookie/Authorization), so
// it is created 0600 to keep credentials away from other local users.
func AppendCommandLog(path string, command Command) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	line := "$ " + command.Name

	if len(command.Args) > 0 {
		line += " " + strings.Join(quoteAll(command.Args), " ")
	}

	if command.StdoutFile != "" {
		line += " > " + command.StdoutFile
	}

	if command.StderrFile != "" {
		line += " 2> " + command.StderrFile
	}

	line += "\n"

	_, err = file.WriteString(line)
	return err
}

// quoteAll renders args as unambiguous shell tokens. Without quoting, headers
// such as "Authorization: Bearer <token>" would render ambiguously and a
// config-supplied header containing a newline would inject fake log lines.
func quoteAll(args []string) []string {
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = shellQuote(arg)
	}
	return quoted
}

// shellQuote returns arg as a POSIX-style token for the command log. Args made
// only of safe characters stay bare; anything else is single-quoted (embedded
// quotes become '\”), and control characters are shown as literal escape
// sequences so a single log line cannot be forged.
func shellQuote(arg string) string {
	if arg != "" && !strings.ContainsAny(arg, "\n\r\t '\\\"$`<>|&;()*?[]{}~!#") {
		return arg
	}
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range arg {
		switch r {
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\'':
			b.WriteString(`'\''`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('\'')
	return b.String()
}
