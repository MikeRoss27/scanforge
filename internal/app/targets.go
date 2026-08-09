package app

import (
	"fmt"
	"os"
	"strings"
)

// ReadTargets parses an engagement targets file: one target per line,
// "#" comments and blank lines ignored, entries deduplicated.
func ReadTargets(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read targets file: %w", err)
	}
	seen := make(map[string]struct{})
	var targets []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		targets = append(targets, line)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("targets file %s contains no targets", path)
	}
	return targets, nil
}

// expandTargets resolves the target(s) of a run or plan: a single positional
// target, or every entry of a --targets file. Exactly one source must be set.
func expandTargets(target, targetsFile string) ([]string, error) {
	if target == "" && targetsFile == "" {
		return nil, fmt.Errorf("target is required (positional argument or --targets file)")
	}
	if target != "" && targetsFile != "" {
		return nil, fmt.Errorf("use either a positional target or --targets, not both")
	}
	if targetsFile != "" {
		targets, err := ReadTargets(targetsFile)
		if err != nil {
			return nil, err
		}
		return targets, nil
	}
	return []string{target}, nil
}
