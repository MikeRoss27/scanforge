// Package asnmap attributes the in-scope resolved IP addresses to their
// network registration (RDAP: network range, name, organisation, country,
// registry handle). It is a native, passive module that only talks to public
// RDAP services (IANA bootstrap, then the responsible registry, with
// rdap.org as fallback); it never contacts the target.
//
// Attribution is annotation only. The module reads the scope-filtered
// resolved_hosts artifact, looks up only IPs that those hosts resolved to,
// and publishes asn_info.jsonl for the report. It never adds a CIDR or a
// neighbouring address to the scope, never publishes a scan target and never
// expands anything from a registered range.
package asnmap

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

const (
	artifactName = "asn_info"
	outputRel    = "01_subdomains/asn_info.jsonl"

	bootstrapV4  = "https://data.iana.org/rdap/ipv4.json"
	bootstrapV6  = "https://data.iana.org/rdap/ipv6.json"
	fallbackRDAP = "https://rdap.org/"

	requestTimeout = 20 * time.Second
	maxBodyBytes   = 4 << 20
	maxIPs         = 100
)

// Record is one line of asn_info.jsonl.
type Record struct {
	IP       string   `json:"ip"`
	Hosts    []string `json:"hosts"`
	ASN      string   `json:"asn,omitempty"`
	ASName   string   `json:"as_name,omitempty"`
	CIDR     string   `json:"cidr,omitempty"`
	CIDRs    []string `json:"cidrs,omitempty"`
	Name     string   `json:"name,omitempty"`
	Org      string   `json:"org,omitempty"`
	Country  string   `json:"country,omitempty"`
	Handle   string   `json:"handle,omitempty"`
	Registry string   `json:"registry,omitempty"`
	Source   string   `json:"source"`
}

// Module implements modules.Module.
type Module struct {
	fetcher modules.Fetcher
	retry   modules.RetryPolicy
}

// New returns the production module.
func New() *Module {
	return &Module{retry: modules.RetryPolicy{Attempts: 3, BaseDelay: time.Second, MaxDelay: 10 * time.Second}}
}

// NewWithFetcher injects the HTTP boundary (tests).
func NewWithFetcher(f modules.Fetcher, retry modules.RetryPolicy) *Module {
	return &Module{fetcher: f, retry: retry}
}

func (m *Module) Name() string { return "asnmap" }
func (m *Module) Description() string {
	return "RDAP network attribution (range, name, org, country) of in-scope resolved IPs; annotation only"
}
func (m *Module) Requires() []string { return []string{"dnsx_raw", "resolved_hosts"} }
func (m *Module) Produces() []string { return []string{artifactName} }

type ipInfo struct {
	hosts  map[string]struct{}
	asn    string
	asName string
}

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, _ runner.Executor) (*modules.Result, error) {
	rawArt, err := runCtx.MustArtifact("dnsx_raw")
	if err != nil {
		return nil, err
	}
	hostsArt, err := runCtx.MustArtifact("resolved_hosts")
	if err != nil {
		return nil, err
	}
	outputPath := runCtx.Run.Path(outputRel)
	result := &modules.Result{
		Name:        m.Name(),
		Status:      "completed",
		OutputFiles: map[string]string{artifactName: outputRel},
	}

	if runCtx.DryRun {
		if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, runner.Command{
			Name: "asnmap (native)",
			Args: []string{"GET", bootstrapV4, "GET", bootstrapV6, "GET", "<registry>/ip/<resolved-ip> (fallback " + fallbackRDAP + "ip/<resolved-ip>)"},
		}); err != nil {
			return nil, fmt.Errorf("failed to write commands log: %w", err)
		}
		return result, publish(runCtx, outputPath, nil)
	}

	ips, err := collectIPs(runCtx, runCtx.Run.Path(rawArt.Path), runCtx.Run.Path(hostsArt.Path))
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(ips))
	for ip := range ips {
		keys = append(keys, ip)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, _ := netip.ParseAddr(keys[i])
		b, _ := netip.ParseAddr(keys[j])
		return a.Compare(b) < 0
	})
	if len(keys) > maxIPs {
		runCtx.EmitWarning(fmt.Sprintf("asnmap: %d IPs resolved, attributing the first %d", len(keys), maxIPs))
		keys = keys[:maxIPs]
	}

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, runner.Command{
		Name: "asnmap (native)",
		Args: []string{"-ips", fmt.Sprint(len(keys)), "-source", "rdap", "-bootstrap", "https://data.iana.org/rdap/", "-fallback", fallbackRDAP},
	}); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	if len(keys) == 0 {
		if err := publish(runCtx, outputPath, nil); err != nil {
			return nil, err
		}
		return modules.SkipNotApplicable(result, nil, "no public resolved IP to attribute")
	}

	fetcher := m.fetcher
	if fetcher == nil {
		var closeConn func()
		fetcher, closeConn, err = modules.NewOSINTFetcher(runCtx.Proxy, requestTimeout, maxBodyBytes)
		if err != nil {
			return nil, err
		}
		defer closeConn()
	}

	c := &client{fetcher: fetcher, retry: m.retry}
	var records []Record
	failed := 0
	for _, ip := range keys {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		rec, lerr := c.lookup(ctx, ip)
		if lerr != nil {
			failed++
			runCtx.EmitWarning(fmt.Sprintf("asnmap: RDAP lookup for %s failed: %v", ip, lerr))
			continue
		}
		info := ips[ip]
		rec.Hosts = sortedKeys(info.hosts)
		if info.asn != "" {
			rec.ASN, rec.ASName = info.asn, info.asName
		}
		records = append(records, rec)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("RDAP attribution failed for all %d IPs", failed)
	}
	if err := publish(runCtx, outputPath, records); err != nil {
		return nil, err
	}
	return result, nil
}

func publish(runCtx *modules.RunContext, path string, records []Record) error {
	var b strings.Builder
	for _, r := range records {
		data, err := json.Marshal(r)
		if err != nil {
			return err
		}
		b.Write(data)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("failed to write asn_info: %w", err)
	}
	// jsonl, not a scoped text artifact: it is annotation data, not targets.
	if err := runCtx.AddArtifact(artifactName, modules.Artifact{Name: artifactName, Type: "jsonl", Path: outputRel}); err != nil {
		return fmt.Errorf("failed to publish asn_info: %w", err)
	}
	return nil
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// collectIPs returns the public IPs that in-scope hosts resolved to. Only
// hosts present in the (already scope-filtered) resolved_hosts artifact and
// still allowed by the scope contribute: IPs belonging to anything else are
// never looked up.
func collectIPs(runCtx *modules.RunContext, rawPath, hostsPath string) (map[string]*ipInfo, error) {
	allowed := make(map[string]struct{})
	hf, err := os.Open(hostsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read resolved hosts: %w", err)
	}
	hs := bufio.NewScanner(hf)
	for hs.Scan() {
		if h := strings.ToLower(strings.TrimSpace(hs.Text())); h != "" {
			allowed[h] = struct{}{}
		}
	}
	_ = hf.Close()
	if err := hs.Err(); err != nil {
		return nil, err
	}

	rf, err := os.Open(rawPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read dnsx results: %w", err)
	}
	defer func() { _ = rf.Close() }()
	ips := make(map[string]*ipInfo)
	sc := bufio.NewScanner(rf)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var rec struct {
			Host string   `json:"host"`
			A    []string `json:"a"`
			AAAA []string `json:"aaaa"`
			ASN  *struct {
				Number string `json:"as-number"`
				Name   string `json:"as-name"`
			} `json:"asn"`
		}
		if json.Unmarshal(sc.Bytes(), &rec) != nil || rec.Host == "" {
			continue
		}
		host := strings.ToLower(rec.Host)
		if _, ok := allowed[host]; !ok {
			continue
		}
		if runCtx.Scope != nil && !runCtx.Scope.IsAllowed(host) {
			continue
		}
		for _, raw := range append(append([]string(nil), rec.A...), rec.AAAA...) {
			addr, perr := netip.ParseAddr(strings.TrimSpace(raw))
			if perr != nil || !publicAddr(addr) {
				continue
			}
			key := addr.String()
			info := ips[key]
			if info == nil {
				info = &ipInfo{hosts: map[string]struct{}{}}
				ips[key] = info
			}
			info.hosts[host] = struct{}{}
			if rec.ASN != nil && rec.ASN.Number != "" && info.asn == "" {
				info.asn, info.asName = rec.ASN.Number, rec.ASN.Name
			}
		}
	}
	return ips, sc.Err()
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// publicAddr reports whether addr is a globally routable unicast address
// worth a registry lookup (private, loopback, link-local and CGNAT ranges
// are neither registered publicly nor something to leak to RDAP servers).
func publicAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && a.IsGlobalUnicast() && !a.IsPrivate() && !a.IsLoopback() &&
		!a.IsLinkLocalUnicast() && !cgnat.Contains(a)
}

// ---- RDAP client ----

type client struct {
	fetcher modules.Fetcher
	retry   modules.RetryPolicy

	v4, v6 []service
	loaded map[string]bool
	cache  []cached
}

type service struct {
	prefix netip.Prefix
	base   string
}

type cached struct {
	start, end netip.Addr
	rec        Record
}

func (c *client) lookup(ctx context.Context, ip string) (Record, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Record{}, err
	}
	for _, e := range c.cache {
		if e.start.Is4() == addr.Is4() && addr.Compare(e.start) >= 0 && addr.Compare(e.end) <= 0 {
			rec := e.rec
			rec.IP = ip
			return rec, nil
		}
	}

	var tried []string
	var lastErr error
	if base := c.bootstrap(ctx, addr); base != "" {
		rec, start, end, qerr := c.query(ctx, base, ip)
		if qerr == nil {
			c.remember(start, end, rec)
			return rec, nil
		}
		tried, lastErr = append(tried, base), qerr
	}
	rec, start, end, qerr := c.query(ctx, fallbackRDAP, ip)
	if qerr == nil {
		c.remember(start, end, rec)
		return rec, nil
	}
	if lastErr != nil {
		return Record{}, fmt.Errorf("registry %s: %v; fallback: %w", strings.Join(tried, ","), lastErr, qerr)
	}
	return Record{}, qerr
}

func (c *client) remember(start, end netip.Addr, rec Record) {
	if start.IsValid() && end.IsValid() {
		c.cache = append(c.cache, cached{start: start, end: end, rec: rec})
	}
}

// bootstrap returns the RDAP base URL responsible for addr per the IANA
// bootstrap registry, or "" when it is unavailable.
func (c *client) bootstrap(ctx context.Context, addr netip.Addr) string {
	if c.loaded == nil {
		c.loaded = map[string]bool{}
	}
	src, dst := bootstrapV4, &c.v4
	if addr.Is6() && !addr.Is4In6() {
		src, dst = bootstrapV6, &c.v6
	}
	if !c.loaded[src] {
		c.loaded[src] = true // one attempt per run
		res, err := modules.FetchWithRetry(ctx, c.fetcher, src, c.retry)
		if err == nil && res.Status == 200 && !res.Truncated {
			*dst = parseBootstrap(res.Body)
		}
	}
	best, bestBits := "", -1
	for _, s := range *dst {
		if s.prefix.Contains(addr.Unmap()) && s.prefix.Bits() > bestBits {
			best, bestBits = s.base, s.prefix.Bits()
		}
	}
	return best
}

func parseBootstrap(body []byte) []service {
	var doc struct {
		Services [][][]string `json:"services"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil
	}
	var out []service
	for _, svc := range doc.Services {
		if len(svc) != 2 || len(svc[1]) == 0 {
			continue
		}
		base := svc[1][0]
		for _, u := range svc[1] { // prefer https
			if strings.HasPrefix(u, "https://") {
				base = u
				break
			}
		}
		if !strings.HasPrefix(base, "https://") {
			continue
		}
		for _, p := range svc[0] {
			if pfx, err := netip.ParsePrefix(p); err == nil {
				out = append(out, service{prefix: pfx, base: base})
			}
		}
	}
	return out
}

type rdapIP struct {
	Handle       string `json:"handle"`
	StartAddress string `json:"startAddress"`
	EndAddress   string `json:"endAddress"`
	Name         string `json:"name"`
	Country      string `json:"country"`
	CIDR0        []struct {
		V4Prefix string `json:"v4prefix"`
		V6Prefix string `json:"v6prefix"`
		Length   int    `json:"length"`
	} `json:"cidr0_cidrs"`
	OriginAS []json.Number `json:"arin_originas0_originautnums"`
	Entities []rdapEntity  `json:"entities"`
}

type rdapEntity struct {
	Roles    []string     `json:"roles"`
	VCard    []any        `json:"vcardArray"`
	Entities []rdapEntity `json:"entities"`
}

func (c *client) query(ctx context.Context, base, ip string) (Record, netip.Addr, netip.Addr, error) {
	endpoint := strings.TrimSuffix(base, "/") + "/ip/" + url.PathEscape(ip)
	res, err := modules.FetchWithRetry(ctx, c.fetcher, endpoint, c.retry)
	if err != nil {
		return Record{}, netip.Addr{}, netip.Addr{}, err
	}
	if res.Status != 200 {
		return Record{}, netip.Addr{}, netip.Addr{}, fmt.Errorf("RDAP %s answered HTTP %d", endpoint, res.Status)
	}
	if res.Truncated {
		return Record{}, netip.Addr{}, netip.Addr{}, fmt.Errorf("RDAP %s response too large", endpoint)
	}
	var doc rdapIP
	if err := json.Unmarshal(res.Body, &doc); err != nil {
		return Record{}, netip.Addr{}, netip.Addr{}, fmt.Errorf("RDAP %s: invalid JSON: %w", endpoint, err)
	}
	start, _ := netip.ParseAddr(doc.StartAddress)
	end, _ := netip.ParseAddr(doc.EndAddress)

	rec := Record{
		IP:      ip,
		Handle:  doc.Handle,
		Name:    doc.Name,
		Country: strings.ToUpper(doc.Country),
		Org:     findOrg(doc.Entities),
		Source:  endpoint,
	}
	if u, perr := url.Parse(endpoint); perr == nil {
		rec.Registry = u.Hostname()
	}
	for _, c := range doc.CIDR0 {
		prefix := c.V4Prefix
		if prefix == "" {
			prefix = c.V6Prefix
		}
		if prefix != "" {
			rec.CIDRs = append(rec.CIDRs, fmt.Sprintf("%s/%d", prefix, c.Length))
		}
	}
	if len(rec.CIDRs) == 0 && start.IsValid() && end.IsValid() {
		rec.CIDRs = rangeToCIDRs(start, end)
	}
	if len(rec.CIDRs) > 0 {
		rec.CIDR = rec.CIDRs[0]
		if len(rec.CIDRs) == 1 {
			rec.CIDRs = nil
		}
	}
	if len(doc.OriginAS) > 0 {
		rec.ASN = "AS" + doc.OriginAS[0].String()
	}
	return rec, start, end, nil
}

// findOrg returns the display name of the registrant (else administrative,
// technical) entity, searched depth-first.
func findOrg(entities []rdapEntity) string {
	for _, role := range []string{"registrant", "administrative", "technical"} {
		if name := orgForRole(entities, role); name != "" {
			return name
		}
	}
	return ""
}

func orgForRole(entities []rdapEntity, role string) string {
	for _, e := range entities {
		for _, r := range e.Roles {
			if strings.EqualFold(r, role) {
				if name := vcardName(e.VCard); name != "" {
					return name
				}
			}
		}
		if name := orgForRole(e.Entities, role); name != "" {
			return name
		}
	}
	return ""
}

func vcardName(vcard []any) string {
	if len(vcard) < 2 {
		return ""
	}
	props, ok := vcard[1].([]any)
	if !ok {
		return ""
	}
	var org string
	for _, p := range props {
		prop, ok := p.([]any)
		if !ok || len(prop) < 4 {
			continue
		}
		key, _ := prop[0].(string)
		switch key {
		case "fn":
			if s, ok := prop[3].(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		case "org":
			switch v := prop[3].(type) {
			case string:
				org = strings.TrimSpace(v)
			case []any:
				if len(v) > 0 {
					org, _ = v[0].(string)
					org = strings.TrimSpace(org)
				}
			}
		}
	}
	return org
}

// rangeToCIDRs converts an inclusive address range into the minimal list of
// CIDR prefixes (bounded, so a malformed huge range cannot loop).
func rangeToCIDRs(start, end netip.Addr) []string {
	if start.Is4() != end.Is4() || start.Compare(end) > 0 {
		return nil
	}
	total := 128
	if start.Is4() {
		total = 32
	}
	toInt := func(a netip.Addr) *big.Int { return new(big.Int).SetBytes(a.AsSlice()) }
	cur, last := toInt(start), toInt(end)
	one := big.NewInt(1)
	var out []string
	for i := 0; i < 64 && cur.Cmp(last) <= 0; i++ {
		size := 0
		for size < total {
			next := size + 1
			span := new(big.Int).Lsh(one, uint(next))
			aligned := new(big.Int).Mod(cur, span).Sign() == 0
			top := new(big.Int).Add(cur, span)
			top.Sub(top, one)
			if !aligned || top.Cmp(last) > 0 {
				break
			}
			size = next
		}
		buf := cur.FillBytes(make([]byte, total/8))
		addr, _ := netip.AddrFromSlice(buf)
		out = append(out, fmt.Sprintf("%s/%d", addr, total-size))
		cur.Add(cur, new(big.Int).Lsh(one, uint(size)))
	}
	return out
}
