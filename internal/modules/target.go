package modules

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// TargetHost extracts a hostname or IP for tools that accept domains rather
// than URLs. It does not expand the scope or produce downstream scan targets.
func TargetHost(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Hostname() == "" || parsed.User != nil {
			return "", fmt.Errorf("invalid enumeration target %q", raw)
		}
		value = parsed.Hostname()
	} else if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	value = strings.TrimSuffix(strings.Trim(value, "[]"), ".")
	if value == "" || strings.ContainsAny(value, "/?#@") {
		return "", fmt.Errorf("invalid enumeration target %q", raw)
	}
	return strings.ToLower(value), nil
}
