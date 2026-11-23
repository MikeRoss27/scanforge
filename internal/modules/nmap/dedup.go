package nmap

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
)

// hostGroup is a set of original targets that share the exact same backing
// IP address(es), so one nmap scan covers all of them. Hosts[0] is the
// leader: the hostname nmap actually scans. Any other member is an alias
// whose result is a copy of the leader's, published under its own name.
type hostGroup struct {
	Hosts []string
	Ports []int
	// ipKey is the joined, sorted IP set the group was matched on; empty
	// for a singleton that was never proven to share a backend. Used only
	// to report the dedup to the operator.
	ipKey string
}

// loadHostIPs reads dnsx's raw JSONL resolution (one line per host, with
// "a"/"aaaa" address lists) and returns, for every host that resolved to
// at least one address, a key built from its sorted, comma-joined IP set.
// Two hosts with the same key are proven to be backed by the identical set
// of addresses.
//
// This is a best-effort optimization hint, never a hard dependency: a
// missing or malformed file yields an empty map, and groupTargets then
// falls back to scanning every host on its own - exactly today's
// behavior. nmap must never perform its own DNS resolution here (that
// would add network latency and test flakiness); it only reuses what dnsx
// already resolved earlier in the pipeline.
func loadHostIPs(path string) map[string]string {
	hostIPs := map[string]string{}
	file, err := os.Open(path)
	if err != nil {
		return hostIPs
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var record struct {
			Host string   `json:"host"`
			A    []string `json:"a"`
			AAAA []string `json:"aaaa"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil || record.Host == "" {
			continue
		}
		ips := append(append([]string{}, record.A...), record.AAAA...)
		if len(ips) == 0 {
			continue
		}
		sort.Strings(ips)
		hostIPs[record.Host] = strings.Join(ips, ",")
	}
	return hostIPs
}

// groupTargets buckets targets that share the same backing IP set (per
// hostIPs) into one hostGroup, so the caller can scan each unique backend
// once instead of once per hostname pointing at it. A host with no known
// IP (hostIPs empty or missing an entry for it) or that is itself an IP
// literal always gets its own singleton group: grouping only ever merges
// hosts *proven* identical by an earlier resolution, never guessed.
//
// Member order inside a group, and group order in the result, follow the
// first appearance in targets, so output stays deterministic.
func groupTargets(targets []hostPorts, hostIPs map[string]string) []hostGroup {
	type bucket struct {
		hosts []string
		ports map[int]struct{}
		ipKey string
	}
	var order []string
	buckets := map[string]*bucket{}
	singleton := 0
	for _, target := range targets {
		key := ""
		if net.ParseIP(target.Host) == nil {
			key = hostIPs[target.Host]
		}
		ipKey := key
		if key == "" {
			// No proven shared backend: a unique key keeps it from ever
			// merging with another target.
			singleton++
			key = fmt.Sprintf("\x00singleton:%d", singleton)
		}
		b, ok := buckets[key]
		if !ok {
			b = &bucket{ports: map[int]struct{}{}, ipKey: ipKey}
			buckets[key] = b
			order = append(order, key)
		}
		b.hosts = append(b.hosts, target.Host)
		for _, port := range target.Ports {
			b.ports[port] = struct{}{}
		}
	}

	groups := make([]hostGroup, 0, len(order))
	for _, key := range order {
		b := buckets[key]
		ports := make([]int, 0, len(b.ports))
		for port := range b.ports {
			ports = append(ports, port)
		}
		sort.Ints(ports)
		groups = append(groups, hostGroup{Hosts: b.hosts, Ports: ports, ipKey: b.ipKey})
	}
	return groups
}

// dedupNote describes the shared backend for the operator, e.g.
// "www.example.com shares 203.0.113.9 with example.com — scanning once".
// Only meaningful for a group with more than one host; callers should
// check len(group.Hosts) > 1 first.
func (g hostGroup) dedupNote() string {
	ip := strings.SplitN(g.ipKey, ",", 2)[0]
	aliases := strings.Join(g.Hosts[1:], ", ")
	return fmt.Sprintf("nmap: %s share the same backend as %s (%s) — scanning %s once for all of them",
		aliases, g.Hosts[0], ip, g.Hosts[0])
}
