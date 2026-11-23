package httpx

import (
	"os"
	"strconv"
	"strings"
)

// nonStandardPortTargets returns the host:port lines of an open_ports
// listing whose port is not already covered by httpx's default 80/443 probe.
func nonStandardPortTargets(lines []string) []string {
	var out []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		i := strings.LastIndex(line, ":")
		if line == "" || i <= 0 || i == len(line)-1 {
			continue
		}
		port, err := strconv.Atoi(line[i+1:])
		if err != nil || port < 1 || port > 65535 || port == 80 || port == 443 {
			continue
		}
		out = append(out, line)
	}
	return out
}

// mergeProbeTargets appends extra targets to base, dropping duplicates and
// blank lines while preserving order.
func mergeProbeTargets(base, extra []string) []string {
	seen := make(map[string]bool, len(base)+len(extra))
	var out []string
	for _, line := range append(append([]string{}, base...), extra...) {
		line = strings.TrimSpace(line)
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}
	return out
}

// writeProbeTargets writes hosts plus non-standard host:port targets to
// outPath and returns how many extra port targets were added. A missing
// ports file adds nothing.
func writeProbeTargets(hostsPath, portsPath, outPath string) (int, error) {
	hosts, err := os.ReadFile(hostsPath)
	if err != nil {
		return 0, err
	}
	ports, err := os.ReadFile(portsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	extra := nonStandardPortTargets(strings.Split(string(ports), "\n"))
	if len(extra) == 0 {
		return 0, nil
	}
	merged := mergeProbeTargets(strings.Split(string(hosts), "\n"), extra)
	return len(extra), os.WriteFile(outPath, []byte(strings.Join(merged, "\n")+"\n"), 0o644)
}
