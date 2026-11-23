package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/active"
	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/MikeRoss27/scanforge/internal/runindex"
	rt "github.com/MikeRoss27/scanforge/internal/runindex/runindextest"
)

type nopLauncher struct{ started int }
type nopProc struct{}

func (nopProc) PID() int         { return 1 }
func (nopProc) Interrupt() error { return nil }
func (nopProc) Kill() error      { return nil }
func (nopProc) Wait() error      { select {} }

func (l *nopLauncher) Start([]string, string) (active.Proc, error) {
	l.started++
	return nopProc{}, nil
}

func newServer(t *testing.T, allow bool) (*Server, *nopLauncher) {
	t.Helper()
	ws := rt.WriteFixture(t)
	dir := t.TempDir()
	scope := filepath.Join(dir, "scope.txt")
	_ = os.WriteFile(scope, []byte("example.com\n*.example.com\n"), 0o644)
	cfg := active.Config{Allow: allow, AuditPath: filepath.Join(dir, "audit.jsonl")}
	if allow {
		cfg.ScopeFile = scope
	}
	l := &nopLauncher{}
	ctl, err := active.New(cfg, l, func(o app.PlanOptions) ([]*app.PlanResult, error) {
		return []*app.PlanResult{{Target: o.Target, Profile: "safe", ScopeSource: "explicit-file", Steps: []app.PlanStep{{Wave: 1, Name: "subfinder", Risk: "passive"}}}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return &Server{Index: runindex.New(ws), Active: ctl, Version: "test"}, l
}

// rpc sends requests and returns decoded responses by id.
func rpc(t *testing.T, s *Server, reqs ...string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := s.Serve(context.Background(), strings.NewReader(strings.Join(reqs, "\n")+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	var res []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad json %q: %v", line, err)
		}
		res = append(res, m)
	}
	return res
}

func call(t *testing.T, s *Server, name, args string) (text string, isErr bool) {
	t.Helper()
	r := rpc(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"`+name+`","arguments":`+args+`}}`)
	if len(r) != 1 {
		t.Fatalf("responses: %v", r)
	}
	res := r[0]["result"].(map[string]any)
	isErr, _ = res["isError"].(bool)
	return res["content"].([]any)[0].(map[string]any)["text"].(string), isErr
}

func TestInitializeAndToolListing(t *testing.T) {
	s, _ := newServer(t, false)
	r := rpc(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"nope"}`)
	if len(r) != 3 {
		t.Fatalf("notification must not be answered: %v", r)
	}
	if r[0]["result"].(map[string]any)["protocolVersion"] != "2025-03-26" {
		t.Fatalf("init: %v", r[0])
	}
	names := map[string]bool{}
	for _, tool := range r[1]["result"].(map[string]any)["tools"].([]any) {
		names[tool.(map[string]any)["name"].(string)] = true
	}
	for _, want := range []string{"list_runs", "get_run", "get_assets", "get_findings", "get_evidence", "plan_scan", "start_authorized_scan", "stop_scan"} {
		if !names["scanforge."+want] {
			t.Errorf("missing tool %s (have %v)", want, names)
		}
	}
	if r[2]["error"].(map[string]any)["code"].(float64) != -32601 {
		t.Fatalf("unknown method: %v", r[2])
	}
}

func TestReadToolsAndSecretsRule(t *testing.T) {
	s, _ := newServer(t, false)
	text, isErr := call(t, s, "scanforge.get_findings", `{"run_id":"`+rt.RunID+`"}`)
	if isErr || !strings.Contains(text, rt.LeakedSecret) {
		t.Fatalf("findings must keep leaked secrets: %v %s", isErr, text)
	}
	if strings.Contains(text, rt.OperatorBearer) {
		t.Fatalf("operator credential leaked: %s", text)
	}
	text, isErr = call(t, s, "scanforge.list_runs", `{}`)
	if isErr || !strings.Contains(text, rt.RunID) {
		t.Fatalf("list_runs: %s", text)
	}
	if text, isErr = call(t, s, "scanforge.plan_scan", `{"target":"example.com"}`); isErr || !strings.Contains(text, "subfinder") {
		t.Fatalf("plan_scan: %s", text)
	}
}

func TestRunIDTraversalRejected(t *testing.T) {
	s, _ := newServer(t, false)
	for _, tool := range []string{"get_run", "get_assets", "get_findings", "get_evidence"} {
		text, isErr := call(t, s, "scanforge."+tool, `{"run_id":"../../etc"}`)
		if !isErr || !strings.Contains(text, "invalid run id") {
			t.Errorf("%s: want invalid run id, got %v %s", tool, isErr, text)
		}
	}
}

func TestActiveToolsDeniedByDefault(t *testing.T) {
	s, l := newServer(t, false)
	for tool, args := range map[string]string{
		"scanforge.start_authorized_scan": `{"target":"example.com"}`,
		"scanforge.stop_scan":             `{"scan_id":"abc"}`,
	} {
		text, isErr := call(t, s, tool, args)
		if !isErr || !strings.Contains(text, "disabled") {
			t.Errorf("%s must be denied: %v %s", tool, isErr, text)
		}
	}
	if l.started != 0 {
		t.Fatal("no process may start")
	}
}

func TestStartRejectsOutOfScopeAndCredentialArguments(t *testing.T) {
	s, l := newServer(t, true)
	if text, isErr := call(t, s, "scanforge.start_authorized_scan", `{"target":"evil.com"}`); !isErr || !strings.Contains(text, "not allowed by the explicit scope") {
		t.Fatalf("out-of-scope: %v %s", isErr, text)
	}
	if _, isErr := call(t, s, "scanforge.start_authorized_scan", `{"target":"example.com","headers":["Cookie: a=b"]}`); !isErr {
		t.Fatal("credential-carrying arguments must be rejected")
	}
	if l.started != 0 {
		t.Fatal("no process may start")
	}
	text, isErr := call(t, s, "scanforge.start_authorized_scan", `{"target":"www.example.com","dry_run":true}`)
	if isErr || !strings.Contains(text, "scan_id") || l.started != 1 {
		t.Fatalf("in-scope start: %v %s", isErr, text)
	}
}
