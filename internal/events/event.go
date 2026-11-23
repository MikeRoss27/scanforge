// Package events provides a typed discovery event bus that complements the
// artifact DAG: the DAG schedules the big stages, while events let a module
// react to individual new discoveries (a DNS name, a JS URL, an API route)
// as they appear.
//
// Every event passes through the same mandatory gate before any subscriber
// sees it: scope check, depth limit, dedup, discovery budget. Out-of-scope
// events are dropped and audited; discovery by OSINT or by crawling never
// implies authorization.
package events

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"strings"
	"time"
)

// Type names a kind of discovery. The set is open: any non-empty string is a
// valid type, the constants below are the well-known ones.
type Type string

const (
	DNSName  Type = "DNS_NAME"
	OpenPort Type = "OPEN_PORT"
	LiveURL  Type = "LIVE_URL"
	JSURL    Type = "JS_URL"
	APIRoute Type = "API_ROUTE"
)

// Verdict values recorded on persisted events.
const (
	VerdictAllowed  = "allowed"
	VerdictRejected = "rejected"
)

// Event is one discovery.
type Event struct {
	// ID is deterministic: a hash of Type and the normalized Value. It is
	// computed by the bus; callers need not set it.
	ID   string `json:"id"`
	Type Type   `json:"type"`
	// Value is the normalized discovered value.
	Value string `json:"value"`
	// Source is the name of the module that emitted the event.
	Source string `json:"source"`
	// ParentID is the ID of the event that led to this one ("" for roots).
	// It must reference an event the bus already accepted.
	ParentID string `json:"parent_id,omitempty"`
	// Timestamp is set by the bus (UTC).
	Timestamp time.Time `json:"timestamp"`
	// ScopeVerdict is set by the bus.
	ScopeVerdict string `json:"scope_verdict"`
	// Depth is derived by the bus from the parent chain (roots are 0).
	Depth int `json:"depth"`
	// ScopeRef optionally names the host or URL the value belongs to when
	// Value is not itself a scope target (e.g. a relative API_ROUTE). When
	// empty, Value is checked directly, so such events fail closed.
	ScopeRef string `json:"scope_ref,omitempty"`
}

// MakeID returns the deterministic ID for a type and (already normalized)
// value.
func MakeID(t Type, normalized string) string {
	sum := sha256.Sum256([]byte(string(t) + "\x00" + normalized))
	return hex.EncodeToString(sum[:8])
}

// Normalize canonicalizes value so equivalent discoveries share one ID.
func Normalize(t Type, value string) string {
	v := strings.TrimSpace(value)
	switch t {
	case DNSName:
		v = strings.ToLower(v)
		v = strings.TrimPrefix(v, "*.")
		return strings.TrimSuffix(v, ".")
	case OpenPort:
		return strings.ToLower(v)
	case LiveURL, JSURL:
		return normalizeURL(v)
	}
	return v
}

func normalizeURL(v string) string {
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		return v
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Fragment = ""
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	port := u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	u.Host = host
	return u.String()
}
