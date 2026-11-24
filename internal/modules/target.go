package modules

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// TargetPort returns the explicit port the user wrote in their own target
// argument ("http://127.0.0.1:8082", "https://example.com:8443/app" or a bare
// "example.com:8443"). It is a probe hint only: scope is host-based and never
// learns about it. ok is false when no valid explicit port (1-65535) is given.
func TargetPort(raw string) (port int, ok bool) {
	value := strings.TrimSpace(raw)
	var portText string
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Hostname() == "" || parsed.User != nil {
			return 0, false
		}
		portText = parsed.Port()
	} else if _, p, err := net.SplitHostPort(value); err == nil {
		portText = p
	}
	n, err := strconv.Atoi(portText)
	if err != nil || n < 1 || n > 65535 {
		return 0, false
	}
	return n, true
}

// TargetProbe returns the "host:port" probe target named by the user's target
// argument (IPv6 hosts are bracketed), or ok=false when it names no port.
// Callers must still require the host to be in scope before using it.
func TargetProbe(raw string) (hostPort string, ok bool) {
	port, ok := TargetPort(raw)
	if !ok {
		return "", false
	}
	host, err := TargetHost(raw)
	if err != nil {
		return "", false
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), true
}

// ScopeTarget is the part of a target argument that scope resolution sees. A
// bare "host:port" is reduced to its host, because scope entries cover hosts
// only and the port is kept separately as a probe hint (TargetPort). URLs and
// plain hosts are returned unchanged; a malformed port stays in place so the
// scope layer rejects it with its usual error.
func ScopeTarget(raw string) string {
	value := strings.TrimSpace(raw)
	if strings.Contains(value, "://") {
		return raw
	}
	if _, ok := TargetPort(value); !ok {
		return raw
	}
	host, err := TargetHost(value)
	if err != nil {
		return raw
	}
	return host
}

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
