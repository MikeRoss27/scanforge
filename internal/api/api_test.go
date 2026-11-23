package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/active"
	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/MikeRoss27/scanforge/internal/runindex"
	rt "github.com/MikeRoss27/scanforge/internal/runindex/runindextest"
)

func newAPI(t *testing.T) http.Handler {
	t.Helper()
	ctl, err := active.New(active.Config{}, nil, func(o app.PlanOptions) ([]*app.PlanResult, error) {
		return []*app.PlanResult{{Target: o.Target}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return New(runindex.New(rt.WriteFixture(t)), ctl, "tok").Handler()
}

func do(h http.Handler, method, path, auth, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://127.0.0.1:8787"+path, strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestReadEndpoints(t *testing.T) {
	h := newAPI(t)
	for _, p := range []string{"/v1/health", "/v1/runs", "/v1/runs/" + rt.RunID, "/v1/runs/" + rt.RunID + "/assets", "/v1/runs/" + rt.RunID + "/evidence?file=06_vulns/nuclei.jsonl"} {
		if rec := do(h, "GET", p, "", ""); rec.Code != 200 {
			t.Errorf("%s -> %d %s", p, rec.Code, rec.Body)
		}
	}
	rec := do(h, "GET", "/v1/runs/"+rt.RunID+"/findings", "", "")
	if !strings.Contains(rec.Body.String(), rt.LeakedSecret) || strings.Contains(rec.Body.String(), rt.OperatorBearer) {
		t.Fatalf("secrets rule violated: %s", rec.Body)
	}
}

func TestTraversalAndAuth(t *testing.T) {
	h := newAPI(t)
	if rec := do(h, "GET", "/v1/runs/example.com/..", "", ""); rec.Code != 400 && rec.Code != 404 && rec.Code != 301 && rec.Code != 307 {
		t.Errorf("traversal -> %d", rec.Code)
	}
	if rec := do(h, "GET", "/v1/runs/example.com/%2e%2e/assets", "", ""); rec.Code == 200 {
		t.Errorf("encoded traversal served")
	}
	if rec := do(h, "GET", "/v1/runs/"+rt.RunID+"/evidence?file=../report.json", "", ""); rec.Code != 400 {
		t.Errorf("evidence traversal -> %d", rec.Code)
	}
	if rec := do(h, "POST", "/v1/plan", "", `{"target":"example.com"}`); rec.Code != 401 {
		t.Errorf("no token -> %d", rec.Code)
	}
	if rec := do(h, "POST", "/v1/plan", "Bearer wrong", `{"target":"example.com"}`); rec.Code != 401 {
		t.Errorf("bad token -> %d", rec.Code)
	}
	if rec := do(h, "POST", "/v1/plan", "Bearer tok", `{"target":"example.com"}`); rec.Code != 200 {
		t.Errorf("plan -> %d %s", rec.Code, rec.Body)
	}
	if rec := do(h, "POST", "/v1/scans", "Bearer tok", `{"target":"example.com"}`); rec.Code != 403 {
		t.Errorf("active disabled -> %d", rec.Code)
	}
}

func TestListenAddrAndHostGuard(t *testing.T) {
	if err := CheckListenAddr("0.0.0.0:80", false); err == nil {
		t.Error("0.0.0.0 must be refused")
	}
	if err := CheckListenAddr("127.0.0.1:8787", false); err != nil {
		t.Error(err)
	}
	h := newAPI(t)
	req := httptest.NewRequest("GET", "http://evil.example/v1/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Errorf("foreign Host -> %d", rec.Code)
	}
}
