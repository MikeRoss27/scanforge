// Package report diffing between two runs of the same target.
package report

import (
	"fmt"
	"sort"
	"strings"
)

// PortKey identifies a port on a given host.
type PortKey struct {
	Host     string `json:"host"`
	Number   int    `json:"number"`
	Protocol string `json:"protocol,omitempty"`
}

// VulnKey identifies a vulnerability across runs. Title is part of the
// identity because two templates may share an id but report different titles.
type VulnKey struct {
	Source     string `json:"source"`
	TemplateID string `json:"template_id"`
	Title      string `json:"title"`
	MatchedAt  string `json:"matched_at"`
}

// RunDelta is the set of changes between a previous run and a later one.
type RunDelta struct {
	AddedAssets   []string  `json:"added_assets"`
	RemovedAssets []string  `json:"removed_assets"`
	AddedPorts    []PortKey `json:"added_ports"`
	RemovedPorts  []PortKey `json:"removed_ports"`
	AddedVulns    []VulnKey `json:"added_vulnerabilities"`
	FixedVulns    []VulnKey `json:"fixed_vulnerabilities"`
}

// CompareReports computes the delta from an earlier run to a later one:
// assets, ports and vulnerabilities that appeared or disappeared. Compare
// with the same target; the caller decides whether the targets match.
func CompareReports(before, after *Report) RunDelta {
	var delta RunDelta

	beforeAssets := sortedAssets(before)
	afterAssets := sortedAssets(after)

	for _, name := range afterAssets {
		if _, ok := before.Assets[name]; !ok {
			delta.AddedAssets = append(delta.AddedAssets, name)
		}
	}
	for _, name := range beforeAssets {
		if _, ok := after.Assets[name]; !ok {
			delta.RemovedAssets = append(delta.RemovedAssets, name)
		}
	}

	beforePorts := collectPorts(before)
	afterPorts := collectPorts(after)
	delta.AddedPorts = portDiff(afterPorts, beforePorts)
	delta.RemovedPorts = portDiff(beforePorts, afterPorts)

	beforeVulns := collectVulns(before)
	afterVulns := collectVulns(after)
	delta.AddedVulns = vulnDiff(afterVulns, beforeVulns)
	delta.FixedVulns = vulnDiff(beforeVulns, afterVulns)

	return delta
}

// Empty reports whether no change was detected.
func (d RunDelta) Empty() bool {
	return len(d.AddedAssets)+len(d.RemovedAssets)+len(d.AddedPorts)+
		len(d.RemovedPorts)+len(d.AddedVulns)+len(d.FixedVulns) == 0
}

func sortedAssets(r *Report) []string {
	names := make([]string, 0, len(r.Assets))
	for name := range r.Assets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func collectPorts(r *Report) []PortKey {
	var keys []PortKey
	for name, asset := range r.Assets {
		for _, port := range sortedPorts(asset) {
			keys = append(keys, PortKey{Host: name, Number: port.Number, Protocol: port.Protocol})
		}
	}
	return keys
}

func sortedPorts(asset *Asset) []*Port {
	ports := make([]*Port, 0, len(asset.Ports))
	for _, port := range asset.Ports {
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].Number < ports[j].Number })
	return ports
}

func portDiff(from, against []PortKey) []PortKey {
	set := make(map[string]struct{}, len(against))
	for _, key := range against {
		set[fmt.Sprintf("%s|%d|%s", key.Host, key.Number, key.Protocol)] = struct{}{}
	}
	var added []PortKey
	for _, key := range from {
		if _, ok := set[fmt.Sprintf("%s|%d|%s", key.Host, key.Number, key.Protocol)]; !ok {
			added = append(added, key)
		}
	}
	sort.Slice(added, func(i, j int) bool {
		if added[i].Host != added[j].Host {
			return added[i].Host < added[j].Host
		}
		return added[i].Number < added[j].Number
	})
	return added
}

func collectVulns(r *Report) []VulnKey {
	var keys []VulnKey
	for _, asset := range r.Assets {
		for _, vuln := range asset.Vulnerabilities {
			keys = append(keys, VulnKey{
				Source:     vuln.Source,
				TemplateID: vuln.TemplateID,
				Title:      vuln.Title,
				MatchedAt:  vuln.MatchedAt,
			})
		}
	}
	return keys
}

func vulnDiff(from, against []VulnKey) []VulnKey {
	known := make(map[VulnKey]struct{}, len(against))
	for _, key := range against {
		known[key] = struct{}{}
	}
	var added []VulnKey
	for _, key := range from {
		if _, ok := known[key]; !ok {
			added = append(added, key)
		}
	}
	sort.Slice(added, func(i, j int) bool {
		if added[i].MatchedAt != added[j].MatchedAt {
			return added[i].MatchedAt < added[j].MatchedAt
		}
		if added[i].TemplateID != added[j].TemplateID {
			return added[i].TemplateID < added[j].TemplateID
		}
		return added[i].Title < added[j].Title
	})
	return added
}

// FormatRunDelta renders a delta as a compact human-readable block. Added
// entries are prefixed with "+", removed with "-" so the output is grep-able.
func FormatRunDelta(delta RunDelta) string {
	var b strings.Builder

	fmt.Fprintf(&b, "RUN DELTA (assets %d, ports %d, vulnerabilities %d)\n",
		len(delta.AddedAssets)-len(delta.RemovedAssets),
		len(delta.AddedPorts)-len(delta.RemovedPorts),
		len(delta.AddedVulns)-len(delta.FixedVulns))

	writeDeltaSection(&b, "ASSETS ADDED", delta.AddedAssets)
	writeDeltaSection(&b, "ASSETS REMOVED", delta.RemovedAssets)

	var addedPorts []string
	for _, p := range delta.AddedPorts {
		addedPorts = append(addedPorts, fmt.Sprintf("%s:%d/%s", p.Host, p.Number, orDash(p.Protocol)))
	}
	writeDeltaSection(&b, "PORTS ADDED", addedPorts)
	var removedPorts []string
	for _, p := range delta.RemovedPorts {
		removedPorts = append(removedPorts, fmt.Sprintf("%s:%d/%s", p.Host, p.Number, orDash(p.Protocol)))
	}
	writeDeltaSection(&b, "PORTS REMOVED", removedPorts)

	writeVulnSection(&b, "VULNERABILITIES ADDED", delta.AddedVulns, "+")
	writeVulnSection(&b, "VULNERABILITIES FIXED", delta.FixedVulns, "-")

	return strings.TrimRight(b.String(), "\n")
}

func writeDeltaSection(b *strings.Builder, title string, entries []string) {
	if len(entries) == 0 {
		return
	}
	fmt.Fprintf(b, "  %s (%d):\n", title, len(entries))
	for _, entry := range entries {
		fmt.Fprintf(b, "    + %s\n", entry)
	}
}

func writeVulnSection(b *strings.Builder, title string, entries []VulnKey, marker string) {
	if len(entries) == 0 {
		return
	}
	fmt.Fprintf(b, "  %s (%d):\n", title, len(entries))
	for _, v := range entries {
		fmt.Fprintf(b, "    %s [%s] %s @ %s\n", marker, v.TemplateID, v.Title, v.MatchedAt)
	}
}

func orDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
