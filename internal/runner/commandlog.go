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
		line += " " + strings.Join(command.Args, " ")
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
