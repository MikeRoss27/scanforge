package report

import (
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/scope"
)

// recursiveDir is where internal/discovery writes the follow-up passes of
// --recursive. Files are named NNN-<value>-<kind>.<ext>; the text kinds
// (resolved, alive, katana) are published through RunContext.AddArtifact and
// therefore already scope-filtered in place, while the raw tool outputs
// (dnsx.jsonl, httpx.jsonl) are not.
const recursiveDir = "07_recursive"

// DiscoveredByRecursive marks assets that only exist thanks to --recursive.
const DiscoveredByRecursive = "recursive"

// foldRecursive merges the recursive-discovery follow-up artifacts into rep,
// reusing the regular parsers on a scratch report so nothing is duplicated.
//
// Scope handling mirrors the rest of ScanForge: the filtered text artifacts
// are authoritative (RunContext.AddArtifact rewrote them in place); a record
// of a raw JSONL output is only merged when its host/URL also appears in the
// filtered text list of the same pass. On top of that, when the run's
// effective scope file can be loaded, every merged host is re-checked against
// it (defense in depth; a host absent from the static scope is dropped).
func foldRecursive(runDir string, rep *Report) error {
	dir := filepath.Join(runDir, recursiveDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var sc *scope.Scope
	if loaded, err := scope.LoadFromFile(filepath.Join(runDir, "00_meta", "effective-scope.txt")); err == nil {
		sc = loaded
	}
	allowed := func(host string) bool { return host != "" && (sc == nil || sc.IsAllowed(host)) }

	known := make(map[string]struct{}, len(rep.Assets))
	for name := range rep.Assets {
		known[name] = struct{}{}
	}

	// Per-pass state, keyed by the NNN-<value> prefix shared by a pass's files.
	type pass struct {
		hosts, alive map[string]struct{} // filtered hosts / URLs
	}
	passes := map[string]*pass{}
	prefixOf := func(name, suffix string) string { return strings.TrimSuffix(name, suffix) }
	get := func(prefix string) *pass {
		if passes[prefix] == nil {
			passes[prefix] = &pass{hosts: map[string]struct{}{}, alive: map[string]struct{}{}}
		}
		return passes[prefix]
	}

	// 1. Filtered text artifacts first: they define what is allowed.
	for _, name := range names {
		path := filepath.Join(dir, name)
		switch {
		case strings.HasSuffix(name, "-resolved.txt"):
			p := get(prefixOf(name, "-resolved.txt"))
			scratch := NewReport(rep.Target, rep.Profile)
			if err := ParseHosts(path, scratch); err != nil {
				return err
			}
			for host := range scratch.Assets {
				if allowed(host) {
					p.hosts[normalizeAssetName(host)] = struct{}{}
					rep.GetOrCreateAsset(host)
				}
			}
		case strings.HasSuffix(name, "-alive.txt"):
			p := get(prefixOf(name, "-alive.txt"))
			if err := scanLines(path, func(line string) {
				if host := normalizeAssetName(line); allowed(host) {
					p.alive[line] = struct{}{}
					p.hosts[host] = struct{}{}
					rep.GetOrCreateAsset(host)
				}
			}); err != nil {
				return err
			}
		case strings.HasSuffix(name, "-katana.txt"):
			scratch := NewReport(rep.Target, rep.Profile)
			if err := ParseKatana(path, scratch); err != nil {
				return err
			}
			mergeScratch(rep, scratch, allowed, nil)
		}
	}

	// 2. Raw JSONL enrichment, restricted to what the filtered lists allow.
	for _, name := range names {
		path := filepath.Join(dir, name)
		switch {
		case strings.HasSuffix(name, "-dnsx.jsonl"):
			p := get(prefixOf(name, "-dnsx.jsonl"))
			scratch := NewReport(rep.Target, rep.Profile)
			if err := ParseDnsx(path, scratch); err != nil {
				return err
			}
			mergeScratch(rep, scratch, func(host string) bool {
				_, ok := p.hosts[host]
				return ok && allowed(host)
			}, nil)
		case strings.HasSuffix(name, "-httpx.jsonl"):
			p := get(prefixOf(name, "-httpx.jsonl"))
			scratch := NewReport(rep.Target, rep.Profile)
			if err := ParseHttpx(path, scratch); err != nil {
				return err
			}
			mergeScratch(rep, scratch, func(host string) bool {
				_, ok := p.hosts[host]
				return ok && allowed(host)
			}, func(svc HTTPService) bool {
				_, ok := p.alive[svc.URL]
				return ok
			})
		}
	}

	// Mark assets that only recursion revealed.
	for name, asset := range rep.Assets {
		if _, ok := known[name]; !ok {
			asset.DiscoveredBy = DiscoveredByRecursive
		}
	}
	return nil
}

// mergeScratch copies the assets of a scratch report into rep. hostOK filters
// assets; svcOK (optional) filters HTTP services.
func mergeScratch(rep, scratch *Report, hostOK func(string) bool, svcOK func(HTTPService) bool) {
	names := make([]string, 0, len(scratch.Assets))
	for name := range scratch.Assets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !hostOK(name) {
			continue
		}
		src := scratch.Assets[name]
		dst := rep.GetOrCreateAsset(name)
		for _, ip := range src.IPs {
			dst.IPs = appendUnique(dst.IPs, ip)
		}
		for _, c := range src.CNAMEs {
			dst.CNAMEs = appendUnique(dst.CNAMEs, c)
		}
		for _, c := range src.CDN {
			dst.CDN = appendUnique(dst.CDN, c)
		}
		for _, a := range src.ASN {
			dst.ASN = appendUnique(dst.ASN, a)
		}
		for _, t := range src.Technologies {
			dst.Technologies = appendUnique(dst.Technologies, t)
		}
		for _, svc := range src.HTTP {
			if svcOK != nil && !svcOK(svc) {
				continue
			}
			if !hasHTTP(dst.HTTP, svc.URL) {
				dst.HTTP = append(dst.HTTP, svc)
			}
		}
		for _, p := range src.Paths {
			if pu, err := url.Parse(p.URL); err == nil && hostOK(pu.Hostname()) {
				dst.Paths = appendUniquePath(dst.Paths, p)
			}
		}
	}
}

func hasHTTP(list []HTTPService, u string) bool {
	for _, s := range list {
		if s.URL == u {
			return true
		}
	}
	return false
}
