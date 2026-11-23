package nmap

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

func TestLoadHostIPs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsx.jsonl")
	content := strings.Join([]string{
		`{"host":"a.example.com","a":["203.0.113.9"]}`,
		`{"host":"b.example.com","a":["203.0.113.9"]}`,
		`{"host":"c.example.com","a":["203.0.113.50"]}`,
		`{"host":"d.example.com","a":[]}`,
		`not json at all`,
		``,
		`{"host":"","a":["203.0.113.9"]}`,
		`{"host":"e.example.com","aaaa":["2001:db8::1"]}`,
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	got := loadHostIPs(path)
	if got["a.example.com"] != got["b.example.com"] {
		t.Fatalf("a and b should share a key: a=%q b=%q", got["a.example.com"], got["b.example.com"])
	}
	if got["a.example.com"] == got["c.example.com"] {
		t.Fatalf("a and c resolve differently and must not share a key")
	}
	if _, ok := got["d.example.com"]; ok {
		t.Fatalf("a host with no addresses must not get a key")
	}
	if got["e.example.com"] == "" {
		t.Fatalf("an AAAA-only host must still get a key")
	}
}

func TestLoadHostIPsMissingFile(t *testing.T) {
	if got := loadHostIPs(filepath.Join(t.TempDir(), "missing.jsonl")); len(got) != 0 {
		t.Fatalf("expected an empty map for a missing file, got %v", got)
	}
}

func TestGroupTargets(t *testing.T) {
	targets := []hostPorts{
		{Host: "alpha.example.com", Ports: []int{80}},
		{Host: "www.alpha.example.com", Ports: []int{443}},
		{Host: "beta.example.com", Ports: []int{22}},
		{Host: "203.0.113.5", Ports: []int{8080}},
	}
	hostIPs := map[string]string{
		"alpha.example.com":     "203.0.113.9",
		"www.alpha.example.com": "203.0.113.9",
		"beta.example.com":      "203.0.113.50",
		// A literal IP target must never be looked up or merged even if an
		// (implausible) entry exists for it.
		"203.0.113.5": "203.0.113.9",
	}

	groups := groupTargets(targets, hostIPs)
	if len(groups) != 3 {
		t.Fatalf("expected 3 groups (alpha+www merged, beta alone, IP literal alone), got %d: %+v", len(groups), groups)
	}

	alpha := groups[0]
	if !reflect.DeepEqual(alpha.Hosts, []string{"alpha.example.com", "www.alpha.example.com"}) {
		t.Fatalf("alpha group hosts = %v", alpha.Hosts)
	}
	if !reflect.DeepEqual(alpha.Ports, []int{80, 443}) {
		t.Fatalf("alpha group ports should be the union, got %v", alpha.Ports)
	}

	beta := groups[1]
	if len(beta.Hosts) != 1 || beta.Hosts[0] != "beta.example.com" {
		t.Fatalf("beta should stay alone, got %+v", beta)
	}

	ipLiteral := groups[2]
	if len(ipLiteral.Hosts) != 1 || ipLiteral.Hosts[0] != "203.0.113.5" {
		t.Fatalf("IP literal target must never be merged, got %+v", ipLiteral)
	}
}

func TestGroupTargetsWithoutHints(t *testing.T) {
	targets := []hostPorts{
		{Host: "a.example.com", Ports: []int{80}},
		{Host: "b.example.com", Ports: []int{80}},
	}
	groups := groupTargets(targets, map[string]string{})
	if len(groups) != 2 {
		t.Fatalf("with no resolution hints, every host must stay its own group, got %d", len(groups))
	}
}

func TestDedupNote(t *testing.T) {
	g := hostGroup{Hosts: []string{"example.com", "www.example.com"}, ipKey: "203.0.113.9"}
	note := g.dedupNote()
	if !strings.Contains(note, "www.example.com") || !strings.Contains(note, "example.com") || !strings.Contains(note, "203.0.113.9") {
		t.Fatalf("dedupNote() = %q, missing expected content", note)
	}
}

func TestChunkBase(t *testing.T) {
	if got := chunkBase(0, 0, 1); got != "host-0001" {
		t.Fatalf("chunkBase(0,0,1) = %q, want host-0001", got)
	}
	if got := chunkBase(1, 2, 3); got != "host-0002-3" {
		t.Fatalf("chunkBase(1,2,3) = %q, want host-0002-3", got)
	}
}

func TestRewriteHostnameXML(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want string
	}{
		{
			"replaces an existing block",
			`<host><address addr="1.2.3.4" addrtype="ipv4"/><hostnames><hostname name="leader.example.com" type="user"/></hostnames><ports/></host>`,
			`<hostnames><hostname name="alias.example.com" type="user"/></hostnames>`,
		},
		{
			"replaces a self-closed empty block",
			`<host><address addr="1.2.3.4" addrtype="ipv4"/><hostnames/><ports/></host>`,
			`<hostnames><hostname name="alias.example.com" type="user"/></hostnames>`,
		},
		{
			"inserts one when absent",
			`<host><address addr="1.2.3.4" addrtype="ipv4"/><ports/></host>`,
			`<hostnames><hostname name="alias.example.com" type="user"/></hostnames>`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(rewriteHostnameXML([]byte(tt.doc), "alias.example.com"))
			if !strings.Contains(got, tt.want) {
				t.Fatalf("rewriteHostnameXML() = %q, want it to contain %q", got, tt.want)
			}
			if strings.Contains(got, "leader.example.com") {
				t.Fatalf("rewriteHostnameXML() kept the leader's name: %q", got)
			}
		})
	}
}

func TestRewriteHostnameXMLEscapesSpecialChars(t *testing.T) {
	got := string(rewriteHostnameXML([]byte(`<host><hostnames/></host>`), `a&b.example.com`))
	if !strings.Contains(got, "a&amp;b.example.com") {
		t.Fatalf("rewriteHostnameXML() did not escape %q: %q", "a&b.example.com", got)
	}
}

func TestPublishAlias(t *testing.T) {
	dir := t.TempDir()
	leaderXML := filepath.Join(dir, "leader.xml")
	leaderTxt := filepath.Join(dir, "leader.txt")
	aliasXML := filepath.Join(dir, "alias.xml")
	aliasTxt := filepath.Join(dir, "alias.txt")

	xmlDoc := `<host><address addr="1.2.3.4" addrtype="ipv4"/><hostnames><hostname name="leader.example.com" type="user"/></hostnames></host>`
	if err := os.WriteFile(leaderXML, []byte(xmlDoc), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leaderTxt, []byte("Nmap scan report for leader.example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := publishAlias(leaderXML, aliasXML, leaderTxt, aliasTxt, "leader.example.com", "alias.example.com"); err != nil {
		t.Fatalf("publishAlias() error = %v", err)
	}

	aliasDoc, err := os.ReadFile(aliasXML)
	if err != nil {
		t.Fatalf("alias XML was not written: %v", err)
	}
	if !strings.Contains(string(aliasDoc), "alias.example.com") || strings.Contains(string(aliasDoc), `name="leader.example.com"`) {
		t.Fatalf("alias XML not correctly patched: %s", aliasDoc)
	}

	aliasTxtDoc, err := os.ReadFile(aliasTxt)
	if err != nil {
		t.Fatalf("alias txt was not written: %v", err)
	}
	if !strings.Contains(string(aliasTxtDoc), "alias.example.com") {
		t.Fatalf("alias txt missing explanatory header: %s", aliasTxtDoc)
	}
}

func TestPublishAliasMissingLeaderXML(t *testing.T) {
	dir := t.TempDir()
	err := publishAlias(filepath.Join(dir, "missing.xml"), filepath.Join(dir, "alias.xml"), filepath.Join(dir, "missing.txt"), filepath.Join(dir, "alias.txt"), "leader", "alias")
	if err == nil {
		t.Fatal("expected an error when the leader's XML is missing")
	}
}

// fakeNmapExecutor simulates nmap by writing a minimal, valid scan XML to
// the command's -oX path (like real nmap would) in addition to recording
// the command, so publishAlias has a genuine file to copy from.
type fakeNmapExecutor struct {
	mu       sync.Mutex
	commands []runner.Command
}

func (e *fakeNmapExecutor) Run(_ context.Context, command runner.Command) (*runner.CommandResult, error) {
	e.mu.Lock()
	e.commands = append(e.commands, command)
	e.mu.Unlock()

	host := command.Args[len(command.Args)-1]
	oXIndex := index(command.Args, "-oX")
	if oXIndex >= 0 {
		doc := `<host><address addr="203.0.113.9" addrtype="ipv4"/><hostnames><hostname name="` + host + `" type="user"/></hostnames>` +
			`<ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host>`
		if err := os.WriteFile(command.Args[oXIndex+1], []byte(doc), 0644); err != nil {
			return nil, err
		}
	}
	oNIndex := index(command.Args, "-oN")
	if oNIndex >= 0 {
		_ = os.WriteFile(command.Args[oNIndex+1], []byte("Nmap scan report for "+host+"\n"), 0644)
	}
	return &runner.CommandResult{Command: command, ExitCode: 0}, nil
}

func (e *fakeNmapExecutor) commandCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.commands)
}

func TestRunDedupesHostsSharingTheSameIP(t *testing.T) {
	root := t.TempDir()
	run := testRun(t, root)
	if err := os.WriteFile(run.Path("03_ports", "naabu.txt"), []byte(strings.Join([]string{
		"example.com:80",
		"www.example.com:80",
	}, "\n")), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(run.Path("01_subdomains"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(run.Path("01_subdomains", "dnsx.jsonl"), []byte(strings.Join([]string{
		`{"host":"example.com","a":["203.0.113.9"]}`,
		`{"host":"www.example.com","a":["203.0.113.9"]}`,
	}, "\n")), 0644); err != nil {
		t.Fatal(err)
	}

	runCtx := modules.NewRunContext("example.com", "ports", false, run)
	if err := runCtx.AddArtifact("open_ports", modules.Artifact{Name: "open_ports", Type: "text", Path: "03_ports/naabu.txt"}); err != nil {
		t.Fatal(err)
	}
	if err := runCtx.AddArtifact("dnsx_raw", modules.Artifact{Name: "dnsx_raw", Type: "jsonl", Path: "01_subdomains/dnsx.jsonl"}); err != nil {
		t.Fatal(err)
	}

	var warnings []string
	runCtx.SetWarningSink(func(msg string) { warnings = append(warnings, msg) })

	var lastProgress modules.ModuleProgressEvent
	runCtx.SetProgressSink(func(e modules.ModuleProgressEvent) { lastProgress = e })

	executor := &fakeNmapExecutor{}
	result, err := New("nmap-test").Run(context.Background(), runCtx, executor)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("status = %q, want completed", result.Status)
	}

	if got := executor.commandCount(); got != 1 {
		t.Fatalf("expected exactly 1 nmap invocation for two hostnames on the same IP, got %d", got)
	}

	if len(warnings) != 1 || !strings.Contains(warnings[0], "www.example.com") {
		t.Fatalf("expected one dedup warning naming the alias, got %v", warnings)
	}

	// The alias (www.example.com, original index 1) must still have its
	// own, correctly attributed XML file even though nmap never actually
	// scanned it directly.
	aliasXML, err := os.ReadFile(run.Path("03_ports", "nmap", "host-0002.xml"))
	if err != nil {
		t.Fatalf("alias XML not published: %v", err)
	}
	if !strings.Contains(string(aliasXML), `name="www.example.com"`) {
		t.Fatalf("alias XML not attributed to www.example.com: %s", aliasXML)
	}

	if lastProgress.Current != 2 || lastProgress.Total != 2 {
		t.Fatalf("final progress = %+v, want Current=2 Total=2 (both original hostnames counted)", lastProgress)
	}
}

func TestRunKeepsHostsSeparateWithoutResolutionHint(t *testing.T) {
	root := t.TempDir()
	run := testRun(t, root)
	if err := os.WriteFile(run.Path("03_ports", "naabu.txt"), []byte(strings.Join([]string{
		"example.com:80",
		"other.com:80",
	}, "\n")), 0644); err != nil {
		t.Fatal(err)
	}

	runCtx := modules.NewRunContext("example.com", "ports", false, run)
	if err := runCtx.AddArtifact("open_ports", modules.Artifact{Name: "open_ports", Type: "text", Path: "03_ports/naabu.txt"}); err != nil {
		t.Fatal(err)
	}
	// Deliberately no dnsx_raw artifact: nmap has no proof these hosts
	// share a backend, so it must fall back to scanning both.

	executor := &fakeNmapExecutor{}
	if _, err := New("nmap-test").Run(context.Background(), runCtx, executor); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := executor.commandCount(); got != 2 {
		t.Fatalf("without a resolution hint, expected 2 separate invocations, got %d", got)
	}
}
