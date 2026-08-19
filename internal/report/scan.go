package report

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var urlPattern = regexp.MustCompile(`https?://[^\s]+`)
var wafPattern = regexp.MustCompile(`(?i)is behind (?:a |an )?(.+?)(?: WAF)?(?:\.|$)`)
var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

func stripANSI(s string) string {
	return ansiEscapePattern.ReplaceAllString(s, "")
}

func scanJSONLines(path string, consume func([]byte)) error {
	return scanLines(path, func(line string) { consume([]byte(line)) })
}

func scanLines(path string, consume func(string)) error {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(stripANSI(scanner.Text()))
		if line != "" {
			consume(line)
		}
	}
	return scanner.Err()
}

func normalizeAssetName(value string) string {
	value = strings.TrimSpace(stripANSI(value))
	if value == "" {
		return ""
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
		return strings.ToLower(parsed.Hostname())
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return strings.ToLower(strings.Trim(host, "[]"))
	}
	return strings.ToLower(strings.Trim(strings.TrimSuffix(value, "."), "[]"))
}

func rawString(value json.RawMessage) string {
	if len(value) == 0 || string(value) == "null" {
		return ""
	}
	var text string
	if json.Unmarshal(value, &text) == nil {
		return text
	}
	var number json.Number
	if json.Unmarshal(value, &number) == nil {
		return number.String()
	}
	return fmt.Sprint(string(value))
}

func rawInt(value json.RawMessage) int {
	text := rawString(value)
	number, _ := strconv.Atoi(text)
	return number
}

func appendUnique(slice []string, val string) []string {
	for _, item := range slice {
		if item == val {
			return slice
		}
	}
	return append(slice, val)
}
