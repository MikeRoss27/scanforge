package asnmap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/report"
	scanScope "github.com/MikeRoss27/scanforge/internal/scope"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

var fastRetry = modules.RetryPolicy{Attempts: 2, BaseDelay: time.Millisecond, MaxDelay: 2 * time.Millisecond}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// routeFetcher serves fixtures by exact URL and records every request, so a
// test can assert precisely which IPs were (not) looked up.
type routeFetcher struct {
	mu     sync.Mutex
	routes map[string][]byte
	asked  []string
}

func (f *routeFetcher) Get(_ context.Context, raw string) (*modules.FetchResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, raw)
	if body, ok := f.routes[raw]; ok {
		return &modules.FetchResult{Status: 200, Body: body}, nil
	}
	return &modules.FetchResult{Status: 404, Body: []byte(`{"errorCode":404}`)}, nil
}

func newRun(t *testing.T) *storage.Run {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"00_meta", "01_subdomains"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0755); err != nil {
			t.Fatal(err)
		}
	}
	return &storage.Run{RootDir: root, MetaDir: filepath.Join(root, "00_meta"), CommandsLog: filepath.Join(root, "00_meta", "commands.log")}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

// setup writes a dnsx result set: www resolves to a public IP covered by the
// ARIN fixture, api to a public IP in the RIPE-style range fixture, and
// evil.other.net (out of scope) and local to IPs that must never be queried.
func setup(t *testing.T, dry bool) (*modules.RunContext, *scanScope.Scope) {
	t.Helper()
	run := newRun(t)
	write(t, run.Path("01_subdomains", "dnsx.jsonl"),
		`{"host":"www.example.com","a":["8.8.8.8"],"asn":{"as-number":"AS15169","as-name":"GOOGLE"}}`+"\n"+
			`{"host":"alias.example.com","a":["8.8.8.9"]}`+"\n"+
			`{"host":"api.example.com","a":["203.0.113.7"],"aaaa":["2001:db8::1"]}`+"\n"+
			`{"host":"intranet.example.com","a":["10.1.2.3","127.0.0.1","100.64.0.1"]}`+"\n"+
			`{"host":"evil.other.net","a":["198.51.100.99"]}`+"\n")
	write(t, run.Path("01_subdomains", "dnsx.txt"), "www.example.com\nalias.example.com\napi.example.com\nintranet.example.com\n")
	scope, err := scanScope.FromTarget("example.com", scanScope.ModeDomain, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "recon", dry, run, scope)
	for name, path := range map[string]string{"dnsx_raw": "01_subdomains/dnsx.jsonl", "resolved_hosts": "01_subdomains/dnsx.txt"} {
		typ := "jsonl"
		if name == "resolved_hosts" {
			typ = "text"
		}
		if err := runCtx.AddArtifact(name, modules.Artifact{Name: name, Type: typ, Path: path}); err != nil {
			t.Fatal(err)
		}
	}
	return runCtx, scope
}

func routes(t *testing.T) map[string][]byte {
	return map[string][]byte{
		bootstrapV4: fixture(t, "bootstrap_ipv4.json"),
		// The more specific /16 entry with an https URL wins over the /8.
		"https://rdap.specific.example/ip/8.8.8.8":  fixture(t, "rdap_ip_arin.json"),
		"https://rdap.apnic.example/ip/203.0.113.7": fixture(t, "rdap_ip_ripe_range.json"),
	}
}

func TestRunAttributesOnlyInScopeIPsAndNeverTouchesScope(t *testing.T) {
	runCtx, scope := setup(t, false)
	f := &routeFetcher{routes: routes(t)}
	res, err := NewWithFetcher(f, fastRetry).Run(context.Background(), runCtx, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != "completed" {
		t.Fatalf("status %q", res.Status)
	}

	// Looked up: 8.8.8.8 (once; 8.8.8.9 is served from the range cache),
	// 203.0.113.7, and the IPv6 address (bootstrap v6 + fallback fail softly).
	for _, asked := range f.asked {
		for _, forbidden := range []string{"10.1.2.3", "127.0.0.1", "100.64.0.1", "198.51.100.99"} {
			if strings.Contains(asked, forbidden) {
				t.Fatalf("looked up non-attributable address: %s", asked)
			}
		}
	}
	if count := strings.Count(strings.Join(f.asked, "\n"), "/ip/8.8.8."); count != 1 {
		t.Fatalf("expected a single lookup for the /24 (cache), got %d: %v", count, f.asked)
	}

	art, ok := runCtx.GetArtifact("asn_info")
	if !ok || art.Type != "jsonl" || art.Scoped {
		t.Fatalf("asn_info artifact = %+v ok=%v", art, ok)
	}
	// Annotation only: no scan-target artifact, no scope change.
	for name := range runCtx.Artifacts {
		if name != "asn_info" && name != "dnsx_raw" && name != "resolved_hosts" {
			t.Fatalf("unexpected artifact published: %s", name)
		}
	}
	for _, probe := range []string{"8.8.8.0", "8.8.8.8", "203.0.113.7", "evil.other.net"} {
		if scope.IsAllowed(probe) {
			t.Fatalf("scope widened to %s", probe)
		}
	}
	if _, err := os.Stat(runCtx.Run.Path("00_meta", "scope-additions.jsonl")); err == nil {
		t.Fatal("asnmap must not record scope additions")
	}

	recs := readRecords(t, runCtx.Run.Path(art.Path))
	if len(recs) != 3 {
		t.Fatalf("records = %+v", recs)
	}
	google := recs[0]
	if google.IP != "8.8.8.8" || google.ASN != "AS15169" || google.ASName != "GOOGLE" ||
		google.CIDR != "8.8.8.0/24" || google.Name != "GOGL" || google.Org != "Google LLC" ||
		google.Country != "US" || google.Handle != "NET-8-8-8-0-2" || google.Registry != "rdap.specific.example" {
		t.Fatalf("google record = %+v", google)
	}
	if !reflect.DeepEqual(google.Hosts, []string{"www.example.com"}) {
		t.Fatalf("hosts = %v", google.Hosts)
	}
	cached := recs[1]
	if cached.IP != "8.8.8.9" || cached.Org != "Google LLC" || !reflect.DeepEqual(cached.Hosts, []string{"alias.example.com"}) {
		t.Fatalf("cached record = %+v", cached)
	}
	// RIPE-style range without cidr0: 203.0.113.0-.191 is /25 + /26.
	ripe := recs[2]
	if ripe.IP != "203.0.113.7" || ripe.CIDR != "203.0.113.0/25" || !reflect.DeepEqual(ripe.CIDRs, []string{"203.0.113.0/25", "203.0.113.128/26"}) ||
		ripe.Org != "Example Networks Pty" || ripe.Country != "AU" {
		t.Fatalf("ripe record = %+v", ripe)
	}
}

func TestRunFallsBackToRDAPOrg(t *testing.T) {
	runCtx, _ := setup(t, false)
	r := routes(t)
	delete(r, bootstrapV4) // IANA unreachable -> 404 for the bootstrap
	r[fallbackRDAP+"ip/8.8.8.8"] = fixture(t, "rdap_ip_arin.json")
	r[fallbackRDAP+"ip/203.0.113.7"] = fixture(t, "rdap_ip_ripe_range.json")
	f := &routeFetcher{routes: r}
	if _, err := NewWithFetcher(f, fastRetry).Run(context.Background(), runCtx, nil); err != nil {
		t.Fatal(err)
	}
	art, _ := runCtx.GetArtifact("asn_info")
	recs := readRecords(t, runCtx.Run.Path(art.Path))
	if len(recs) != 3 || recs[0].Registry != "rdap.org" {
		t.Fatalf("fallback records = %+v", recs)
	}
}

func TestRunAllLookupsFailing(t *testing.T) {
	runCtx, _ := setup(t, false)
	_, err := NewWithFetcher(&routeFetcher{routes: map[string][]byte{}}, fastRetry).Run(context.Background(), runCtx, nil)
	if err == nil || !strings.Contains(err.Error(), "failed for all") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunDryRunRecordsPlanWithoutNetwork(t *testing.T) {
	runCtx, _ := setup(t, true)
	f := &routeFetcher{}
	res, err := NewWithFetcher(f, fastRetry).Run(context.Background(), runCtx, nil)
	if err != nil || res.Status != "completed" {
		t.Fatalf("dry run: %v %v", res, err)
	}
	if len(f.asked) != 0 {
		t.Fatalf("dry run touched the network: %v", f.asked)
	}
	log, _ := os.ReadFile(runCtx.Run.CommandsLog)
	for _, want := range []string{bootstrapV4, bootstrapV6, "rdap.org"} {
		if !strings.Contains(string(log), want) {
			t.Fatalf("command log %q lacks %q", log, want)
		}
	}
	if _, ok := runCtx.GetArtifact("asn_info"); !ok {
		t.Fatal("asn_info must be published in dry run")
	}
}

func TestRDAPOverHTTPTestServer(t *testing.T) {
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write(fixture(t, "rdap_ip_arin.json"))
	}))
	defer srv.Close()
	inner, closeConn, err := modules.NewOSINTFetcher("", 5*time.Second, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer closeConn()
	c := &client{fetcher: inner, retry: fastRetry}
	rec, _, _, err := c.query(context.Background(), srv.URL+"/rdap/", "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0] != "/rdap/ip/8.8.8.8" || rec.Org != "Google LLC" {
		t.Fatalf("asked=%v rec=%+v", asked, rec)
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func readRecords(t *testing.T, path string) []Record {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []Record
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func TestRangeToCIDRs(t *testing.T) {
	cases := []struct {
		start, end string
		want       []string
	}{
		{"10.0.0.0", "10.0.0.255", []string{"10.0.0.0/24"}},
		{"203.0.113.0", "203.0.113.191", []string{"203.0.113.0/25", "203.0.113.128/26"}},
		{"1.2.3.5", "1.2.3.5", []string{"1.2.3.5/32"}},
		{"2001:db8::", "2001:db8::ffff", []string{"2001:db8::/112"}},
	}
	for _, tc := range cases {
		got := rangeToCIDRs(mustAddr(tc.start), mustAddr(tc.end))
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s-%s = %v, want %v", tc.start, tc.end, got, tc.want)
		}
	}
}

func TestReportShowsAttribution(t *testing.T) {
	runCtx, _ := setup(t, false)
	if _, err := NewWithFetcher(&routeFetcher{routes: routes(t)}, fastRetry).Run(context.Background(), runCtx, nil); err != nil {
		t.Fatal(err)
	}
	rep := report.NewReport("example.com", "recon")
	rep.GetOrCreateAsset("www.example.com")
	if err := report.ParseASNInfo(runCtx.Run.Path(outputRel), rep); err != nil {
		t.Fatal(err)
	}
	if _, exists := rep.Assets["evil.other.net"]; exists || len(rep.Assets) != 1 {
		t.Fatalf("attribution must not create assets: %v", rep.Assets)
	}
	n := rep.Assets["www.example.com"].Network
	if len(n) != 1 || n[0].Org != "Google LLC" || n[0].CIDR != "8.8.8.0/24" || n[0].ASN != "AS15169" {
		t.Fatalf("network = %+v", n)
	}
	md := filepath.Join(t.TempDir(), "report.md")
	if err := rep.WriteMarkdown(md); err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(md)
	if !strings.Contains(string(out), "### Network Attribution") || !strings.Contains(string(out), "Google LLC") || !strings.Contains(string(out), "8.8.8.0/24") {
		t.Fatalf("markdown lacks attribution:\n%s", out)
	}
}
