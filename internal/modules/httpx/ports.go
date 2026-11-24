package httpx

import (
	"os"
	"strconv"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/modules"
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

// targetHintProbe returns the "host:port" probe the user asked for in their
// own target argument (e.g. http://127.0.0.1:8082), or ok=false. The port is
// only a hint: the host must be in scope (scope stays host-based) and must be
// one of the already scope-filtered resolved hosts, so a target port can never
// introduce a host the pipeline did not already accept. The default 80/443 are
// covered by httpx itself and are not repeated.
func targetHintProbe(runCtx *modules.RunContext, hostsPath string) (string, bool) {
	hostPort, ok := modules.TargetProbe(runCtx.Target)
	if !ok {
		return "", false
	}
	if port, _ := modules.TargetPort(runCtx.Target); port == 80 || port == 443 {
		return "", false
	}
	if !runCtx.IsInScope(hostPort) {
		return "", false
	}
	host, err := modules.TargetHost(runCtx.Target)
	if err != nil {
		return "", false
	}
	data, err := os.ReadFile(hostsPath)
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.EqualFold(strings.Trim(strings.TrimSpace(line), "[]"), host) {
			return hostPort, true
		}
	}
	return "", false
}

// appendProbeTarget writes inputPath plus extra to outPath (deduplicated).
func appendProbeTarget(inputPath, outPath, extra string) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}
	merged := mergeProbeTargets(strings.Split(string(data), "\n"), []string{extra})
	return os.WriteFile(outPath, []byte(strings.Join(merged, "\n")+"\n"), 0o644)
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
