package modules

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// maxFailureReasonLines bounds how much of a tool's stderr gets folded into
// Result.Reason: enough to show the actual cause (e.g. "disk quota
// exceeded") without flooding the console on a verbose failure.
const maxFailureReasonLines = 3

// FailureReason reads the tail of a command's captured stderr file and
// formats it as a short, operator-facing reason for a non-zero exit code.
// Without this, a module can only report "failed (exit code N)": the real
// cause (binary misconfigured, disk quota exceeded, auth rejected, ...) sits
// unread in a 00_meta/*.stderr.log file the operator has to go find
// manually. It returns "" if stderrPath is empty, missing, or empty, so
// callers can unconditionally append the result to their status string.
func FailureReason(stderrPath string) string {
	if stderrPath == "" {
		return ""
	}
	f, err := os.Open(stderrPath)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(stripANSI(scanner.Text()))
		if line == "" {
			continue
		}
		lines = append(lines, line)
		if len(lines) > maxFailureReasonLines {
			lines = lines[1:]
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, " | ")
}

// FailureStatus formats the standard "failed (exit code N)" status string,
// appending a stderr excerpt (via FailureReason) when one is available so
// the console and manifest show the real cause inline instead of only the
// exit code.
func FailureStatus(exitCode int, stderrPath string) string {
	status := fmt.Sprintf("failed (exit code %d)", exitCode)
	if reason := FailureReason(stderrPath); reason != "" {
		status = fmt.Sprintf("%s: %s", status, reason)
	}
	return status
}

// stripANSI removes SGR color escape sequences (e.g. the "[FTL]" tool
// labels nuclei/httpx/tlsx print) so a terminal-colored stderr line reads
// cleanly once folded into Result.Reason or the status string.
func stripANSI(s string) string {
	if !strings.Contains(s, "\x1b[") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && s[j] != 'm' {
				j++
			}
			i = j
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
