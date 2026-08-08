// Package scope models canonical scan scopes, exclusions and the filtering
// applied to every produced artifact.
package scope

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Mode controls how the primary target is expanded into an effective scope.
type Mode string

const (
	// ModeExact allows only the target hostname or IP.
	ModeExact Mode = "exact"
	// ModeDomain allows the target domain and all of its subdomains.
	ModeDomain Mode = "domain"
)

// Scope contains allow and deny rules. Exclusions always take precedence.
// Wildcards are stored as their base domain (for example, "example.com").
type Scope struct {
	ExactHosts map[string]struct{}
	Wildcards  []string
	CIDRs      []*net.IPNet

	ExcludedExactHosts map[string]struct{}
	ExcludedWildcards  []string
	ExcludedCIDRs      []*net.IPNet
}

// FromTarget builds an effective scope without requiring a scope file. A CIDR
// can only be introduced through additions, never as the primary target.
func FromTarget(target string, mode Mode, additions, exclusions []string) (*Scope, error) {
	s := newScope()

	entry, err := parseEntry(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target %q: %w", target, err)
	}
	if entry.kind == entryCIDR || entry.kind == entryWildcard {
		return nil, fmt.Errorf("invalid target %q: use a hostname or IP; add CIDRs and wildcards explicitly", target)
	}

	switch mode {
	case ModeExact:
		s.add(entry, false)
	case ModeDomain:
		if net.ParseIP(entry.value) != nil {
			return nil, fmt.Errorf("domain scope requires a DNS domain, got IP %q", entry.value)
		}
		if !strings.Contains(entry.value, ".") {
			return nil, fmt.Errorf("domain scope requires a multi-label DNS domain, got %q", entry.value)
		}
		s.add(entry, false)
		s.add(parsedEntry{kind: entryWildcard, value: entry.value}, false)
	default:
		return nil, fmt.Errorf("unsupported scope mode %q", mode)
	}

	for _, value := range additions {
		entry, err := parseEntry(value)
		if err != nil {
			return nil, fmt.Errorf("invalid scope addition %q: %w", value, err)
		}
		s.add(entry, false)
	}
	for _, value := range exclusions {
		entry, err := parseEntry(value)
		if err != nil {
			return nil, fmt.Errorf("invalid scope exclusion %q: %w", value, err)
		}
		s.add(entry, true)
	}

	return s, nil
}

// LoadFromFile loads canonical scope entries. Lines prefixed with "!" are
// exclusions; comments and empty lines are ignored.
func LoadFromFile(path string) (*Scope, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open scope file %q: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	s := newScope()
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		excluded := strings.HasPrefix(line, "!")
		if excluded {
			line = strings.TrimSpace(strings.TrimPrefix(line, "!"))
		}
		entry, err := parseEntry(line)
		if err != nil {
			return nil, fmt.Errorf("invalid scope entry at %s:%d: %w", path, lineNumber, err)
		}
		s.add(entry, excluded)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("unable to read scope file %q: %w", path, err)
	}
	return s, nil
}

// IsAllowed reports whether target is allowed after applying exclusions.
func (s *Scope) IsAllowed(target string) bool {
	if s == nil {
		return false
	}
	host, err := hostFromInput(target)
	if err != nil {
		return false
	}

	if matches(host, s.ExcludedExactHosts, s.ExcludedWildcards, s.ExcludedCIDRs) {
		return false
	}
	return matches(host, s.ExactHosts, s.Wildcards, s.CIDRs)
}

// Entries returns a deterministic, canonical representation of the effective
// scope. Exclusions are prefixed with "!", making the result suitable for
// WriteFile and LoadFromFile.
func (s *Scope) Entries() []string {
	if s == nil {
		return nil
	}

	var entries []string
	entries = append(entries, sortedMapKeys(s.ExactHosts)...)
	entries = append(entries, sortedWildcards(s.Wildcards, "")...)
	entries = append(entries, sortedCIDRs(s.CIDRs, "")...)
	entries = append(entries, prefixedMapKeys(s.ExcludedExactHosts, "!")...)
	entries = append(entries, sortedWildcards(s.ExcludedWildcards, "!")...)
	entries = append(entries, sortedCIDRs(s.ExcludedCIDRs, "!")...)
	return entries
}

// WriteFile writes the effective scope in the format accepted by LoadFromFile.
func (s *Scope) WriteFile(path string) error {
	if s == nil {
		return fmt.Errorf("scope is nil")
	}
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("scope output path is empty")
	}
	contents := strings.Join(s.Entries(), "\n")
	if contents != "" {
		contents += "\n"
	}
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		return fmt.Errorf("unable to write scope file %q: %w", path, err)
	}
	return nil
}

type entryKind uint8

const (
	entryExact entryKind = iota
	entryWildcard
	entryCIDR
)

type parsedEntry struct {
	kind  entryKind
	value string
	cidr  *net.IPNet
}

func newScope() *Scope {
	return &Scope{
		ExactHosts:         make(map[string]struct{}),
		Wildcards:          []string{},
		CIDRs:              []*net.IPNet{},
		ExcludedExactHosts: make(map[string]struct{}),
		ExcludedWildcards:  []string{},
		ExcludedCIDRs:      []*net.IPNet{},
	}
}

func parseEntry(input string) (parsedEntry, error) {
	value := strings.TrimSpace(input)
	if value == "" {
		return parsedEntry{}, fmt.Errorf("entry is empty")
	}
	if strings.HasPrefix(value, "!") {
		return parsedEntry{}, fmt.Errorf("unexpected exclusion prefix")
	}

	if strings.Contains(value, "/") && !strings.Contains(value, "://") {
		if _, cidr, err := net.ParseCIDR(value); err == nil {
			return parsedEntry{kind: entryCIDR, value: cidr.String(), cidr: cidr}, nil
		}
	}

	if strings.HasPrefix(strings.ToLower(value), "*.") {
		base := strings.TrimPrefix(strings.ToLower(value), "*.")
		host, err := validateHost(base)
		if err != nil {
			return parsedEntry{}, fmt.Errorf("invalid wildcard: %w", err)
		}
		if net.ParseIP(host) != nil {
			return parsedEntry{}, fmt.Errorf("wildcard cannot target an IP")
		}
		return parsedEntry{kind: entryWildcard, value: host}, nil
	}

	host, err := hostFromInput(value)
	if err != nil {
		return parsedEntry{}, err
	}
	return parsedEntry{kind: entryExact, value: host}, nil
}

func hostFromInput(input string) (string, error) {
	value := strings.TrimSpace(input)
	if value == "" {
		return "", fmt.Errorf("host is empty")
	}

	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Hostname() == "" {
			return "", fmt.Errorf("invalid URL")
		}
		if parsed.User != nil {
			return "", fmt.Errorf("URL credentials are not allowed")
		}
		value = parsed.Hostname()
	} else {
		if strings.ContainsAny(value, "/?#@") {
			return "", fmt.Errorf("invalid host %q", value)
		}
		if host, port, err := net.SplitHostPort(value); err == nil {
			if err := validatePort(port); err != nil {
				return "", err
			}
			value = host
		} else if strings.Count(value, ":") == 1 {
			host, port, found := strings.Cut(value, ":")
			if found {
				if net.ParseIP(host) == nil {
					if err := validatePort(port); err != nil {
						return "", err
					}
					value = host
				}
			}
		}
	}

	return validateHost(value)
}

func validatePort(value string) error {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %q", value)
	}
	return nil
}

func validateHost(input string) (string, error) {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(input)), ".")
	if host == "" {
		return "", fmt.Errorf("host is empty")
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	if len(host) > 253 {
		return "", fmt.Errorf("hostname exceeds 253 characters")
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("invalid hostname %q", host)
		}
		for i, char := range label {
			if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || (char == '-' && i > 0 && i < len(label)-1) {
				continue
			}
			return "", fmt.Errorf("invalid hostname %q", host)
		}
	}
	return host, nil
}

func (s *Scope) add(entry parsedEntry, excluded bool) {
	switch entry.kind {
	case entryExact:
		if excluded {
			s.ExcludedExactHosts[entry.value] = struct{}{}
		} else {
			s.ExactHosts[entry.value] = struct{}{}
		}
	case entryWildcard:
		if excluded {
			s.ExcludedWildcards = appendUnique(s.ExcludedWildcards, entry.value)
		} else {
			s.Wildcards = appendUnique(s.Wildcards, entry.value)
		}
	case entryCIDR:
		if excluded {
			s.ExcludedCIDRs = appendUniqueCIDR(s.ExcludedCIDRs, entry.cidr)
		} else {
			s.CIDRs = appendUniqueCIDR(s.CIDRs, entry.cidr)
		}
	}
}

func matches(host string, exact map[string]struct{}, wildcards []string, cidrs []*net.IPNet) bool {
	if _, ok := exact[host]; ok {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, cidr := range cidrs {
			if cidr != nil && cidr.Contains(ip) {
				return true
			}
		}
	}
	for _, base := range wildcards {
		if strings.HasSuffix(host, "."+base) {
			return true
		}
	}
	return false
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func appendUniqueCIDR(values []*net.IPNet, value *net.IPNet) []*net.IPNet {
	for _, existing := range values {
		if existing != nil && existing.String() == value.String() {
			return values
		}
	}
	return append(values, value)
}

func sortedMapKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return keys
}

func prefixedMapKeys(values map[string]struct{}, prefix string) []string {
	keys := sortedMapKeys(values)
	for i := range keys {
		keys[i] = prefix + keys[i]
	}
	return keys
}

func sortedWildcards(values []string, prefix string) []string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = prefix + "*." + value
	}
	sort.Strings(result)
	return result
}

func sortedCIDRs(values []*net.IPNet, prefix string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != nil {
			result = append(result, prefix+value.String())
		}
	}
	sort.Strings(result)
	return result
}

