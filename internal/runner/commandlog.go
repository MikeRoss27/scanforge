package runner

import (
	"os"
	"strings"
)

func AppendCommandLog(path string, command Command) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

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
