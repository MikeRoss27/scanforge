package scope

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

type Scope struct {
	ExactHosts map[string]struct{}
	Wildcards  []string
	CIDRs      []*net.IPNet
}

func LoadFromFile(path string) (*Scope, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open scope file %q: %w", path, err)
	}
	defer file.Close()

	s := &Scope{
		ExactHosts: make(map[string]struct{}),
		Wildcards:  []string{},
		CIDRs:      []*net.IPNet{},
	}

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if _, cidr, err := net.ParseCIDR(line); err == nil {
			s.CIDRs = append(s.CIDRs, cidr)
			continue
		}

		host := normalizeHost(line)

		if host == "" {
			continue
		}

		if strings.HasPrefix(host, "*.") {
			base := strings.TrimPrefix(host, "*.")
			s.Wildcards = append(s.Wildcards, base)
			continue
		}

		s.ExactHosts[host] = struct{}{}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("unable to read scope file %q: %w", path, err)
	}

	return s, nil
}

func (s *Scope) IsAllowed(target string) bool {
	host := normalizeHost(target)

	if host == "" {
		return false
	}

	if _, ok := s.ExactHosts[host]; ok {
		return true
	}

	if ip := net.ParseIP(host); ip != nil {
		for _, cidr := range s.CIDRs {
			if cidr.Contains(ip) {
				return true
			}
		}
	}

	for _, wildcardBase := range s.Wildcards {
		if strings.HasSuffix(host, "."+wildcardBase) {
			return true
		}
	}

	return false
}

func normalizeHost(input string) string {
	input = strings.TrimSpace(strings.ToLower(input))
	input = strings.TrimSuffix(input, "/")

	if input == "" {
		return ""
	}

	if strings.Contains(input, "://") {
		parsed, err := url.Parse(input)
		if err == nil && parsed.Host != "" {
			input = parsed.Host
		}
	}

	if strings.Contains(input, "/") {
		input = strings.Split(input, "/")[0]
	}

	if host, _, err := net.SplitHostPort(input); err == nil {
		input = host
	}

	return strings.TrimSpace(input)
}
