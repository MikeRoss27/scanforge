package events

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"strings"
)

// Extracted is one candidate discovery read from an artifact, before the bus
// has admitted it. ScopeRef is set when Value is not itself a scope target.
type Extracted struct {
	Type     Type
	Value    string
	ScopeRef string
}

// extendedArtifacts lists the artifacts that feed events in recursive mode.
// It is a superset of ArtifactEventTypes (which stays the demo mapping used
// by --events alone).
var extendedArtifacts = map[string]struct{}{
	"subdomains":       {},
	"brute_subdomains": {},
	"resolved_hosts":   {},
	"open_ports":       {},
	"alive_urls":       {},
	"crawled_urls":     {},
	"historical_urls":  {},
	"js_secrets":       {},
}

// HasExtractor reports whether ExtractArtifact knows name.
func HasExtractor(name string) bool {
	_, ok := extendedArtifacts[name]
	return ok
}

// ExtractArtifact reads the artifact file at filePath and returns the typed
// discoveries it contains:
//
//	subdomains, brute_subdomains, resolved_hosts -> DNS_NAME
//	open_ports                                   -> OPEN_PORT
//	alive_urls                                   -> LIVE_URL
//	crawled_urls, historical_urls                -> JS_URL (.js) + DNS_NAME (URL host)
//	js_secrets (jsonl)                           -> JS_URL, API_ROUTE, DNS_NAME
//
// Nothing here decides scope: the bus gates every returned value. Relative
// API routes are resolved against the origin of the JS file that contained
// them, and that origin is their ScopeRef, so a route is only ever as
// in-scope as the host that served it.
func ExtractArtifact(name, filePath string) ([]Extracted, error) {
	if !HasExtractor(name) {
		return nil, nil
	}
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("events: open %q: %w", filePath, err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)

	var out []Extracted
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		switch name {
		case "subdomains", "brute_subdomains", "resolved_hosts":
			if net.ParseIP(line) == nil {
				out = append(out, Extracted{Type: DNSName, Value: line})
			}
		case "open_ports":
			out = append(out, Extracted{Type: OpenPort, Value: line})
		case "alive_urls":
			out = append(out, Extracted{Type: LiveURL, Value: line})
			// The host is known to the DAG; emitting it first keeps a
			// later rediscovery from looking like a new name.
			if u, err := url.Parse(line); err == nil && u.Hostname() != "" && net.ParseIP(u.Hostname()) == nil {
				out = append(out, Extracted{Type: DNSName, Value: u.Hostname()})
			}
		case "crawled_urls", "historical_urls":
			out = append(out, URLDiscoveries(line)...)
		case "js_secrets":
			out = append(out, jsFindingDiscoveries(line)...)
		}
	}
	if err := sc.Err(); err != nil {
		return out, fmt.Errorf("events: read %q: %w", filePath, err)
	}
	return out, nil
}

// URLDiscoveries returns what a crawled or historical URL reveals: the URL
// itself as JS_URL when it points at JavaScript, and its host as DNS_NAME.
func URLDiscoveries(raw string) []Extracted {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil
	}
	var out []Extracted
	if IsJSPath(u.Path) {
		out = append(out, Extracted{Type: JSURL, Value: raw})
	}
	if host := u.Hostname(); net.ParseIP(host) == nil {
		out = append(out, Extracted{Type: DNSName, Value: host})
	}
	return out
}

// IsJSPath reports whether a URL path names a JavaScript file.
func IsJSPath(p string) bool {
	switch strings.ToLower(path.Ext(p)) {
	case ".js", ".mjs":
		return true
	}
	return false
}

// jsFinding mirrors the fields of a jssecrets JSONL record that matter here.
type jsFinding struct {
	URL   string `json:"url"`
	Kind  string `json:"kind"`
	Match string `json:"match"`
}

func jsFindingDiscoveries(line string) []Extracted {
	var f jsFinding
	if json.Unmarshal([]byte(line), &f) != nil || f.URL == "" {
		return nil
	}
	base, err := url.Parse(f.URL)
	if err != nil || base.Host == "" {
		return nil
	}
	var out []Extracted
	if IsJSPath(base.Path) {
		out = append(out, Extracted{Type: JSURL, Value: f.URL})
	}
	switch f.Kind {
	case "endpoint":
		ref, err := url.Parse(f.Match)
		if err != nil || f.Match == "" {
			return out
		}
		abs := base.ResolveReference(ref)
		if abs.Host == "" || (abs.Scheme != "http" && abs.Scheme != "https") {
			return out
		}
		out = append(out, Extracted{
			Type:     APIRoute,
			Value:    abs.String(),
			ScopeRef: abs.Scheme + "://" + abs.Host,
		})
	case "internal-host", "cloud-storage":
		if host := hostOf(f.Match); host != "" && net.ParseIP(host) == nil {
			out = append(out, Extracted{Type: DNSName, Value: host})
		}
	}
	return out
}

// hostOf extracts a bare hostname from "host", "host/path" or a URL.
func hostOf(v string) string {
	v = strings.TrimSpace(v)
	if strings.Contains(v, "://") {
		if u, err := url.Parse(v); err == nil {
			return u.Hostname()
		}
		return ""
	}
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		v = v[:i]
	}
	if h, _, err := net.SplitHostPort(v); err == nil {
		return h
	}
	return v
}
