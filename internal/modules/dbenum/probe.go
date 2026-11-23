package dbenum

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	neturl "net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/modules/dbcore"
)

// Stable finding ids (also used for console titles and tests).
const (
	findReachable             = "reachable"
	findAnonReadableTable     = "anon-readable-table"
	findAuthSettings          = "auth-settings-exposed"
	findSupabaseNeedsKey      = "supabase-needs-key"
	findPublicRTDB            = "public-rtdb"
	findLockedRTDB            = "rtdb-locked"
	findPocketBaseCollections = "pocketbase-collections-exposed"
)

// prober holds the shared HTTP client and the operator's custom headers.
type prober struct {
	client  *http.Client
	headers []string
}

// httpResponse is the small, bounded view of a response the probes need. The
// body is capped and, for the probes here, is never row/document data.
type httpResponse struct {
	status int
	header http.Header
	body   []byte
}

// get issues a read-only GET with the given extra headers (plus the operator's
// configured headers), capping the body so a hostile or huge response cannot
// exhaust memory.
func (p *prober) get(ctx context.Context, rawURL string, extra map[string]string) (*httpResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	modules.ApplyHeaders(req, p.headers)
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}
	return &httpResponse{status: resp.StatusCode, header: resp.Header, body: body}, nil
}

// enumerate dispatches on backend kind. A probe failure (network error, non-2xx)
// never aborts the module: it is recorded as best it can and the next target
// continues.
func (p *prober) enumerate(ctx context.Context, tg target) []EnumRecord {
	switch dbcore.Backend(tg.backend) {
	case dbcore.Supabase:
		return p.enumSupabase(ctx, tg)
	case dbcore.Firebase:
		return p.enumFirebase(ctx, tg)
	case dbcore.Appwrite:
		return p.enumAppwrite(ctx, tg)
	case dbcore.PocketBase:
		return p.enumPocketBase(ctx, tg)
	default:
		return nil
	}
}

func base(tg target) EnumRecord {
	return EnumRecord{Host: tg.host, Backend: tg.backend, Endpoint: tg.endpoint, Count: -1}
}

// ---- Supabase -------------------------------------------------------------

func (p *prober) enumSupabase(ctx context.Context, tg target) []EnumRecord {
	var out []EnumRecord

	// /auth/v1/settings is public and does not need a key.
	if rec, ok := p.supabaseAuthSettings(ctx, tg); ok {
		out = append(out, rec)
	}

	if tg.key == "" {
		r := base(tg)
		r.Finding = findSupabaseNeedsKey
		r.Severity = "info"
		r.Detail = "no anon key recovered from client code; table enumeration skipped"
		return append(out, r)
	}

	hdr := map[string]string{"apikey": tg.key, "Authorization": "Bearer " + tg.key}
	root, err := p.get(ctx, tg.endpoint+"/rest/v1/", hdr)
	if err != nil || root.status != http.StatusOK {
		r := base(tg)
		r.Finding = findReachable
		r.Severity = "info"
		if root != nil {
			r.Status = root.status
		}
		r.Detail = "PostgREST root not readable with the recovered key"
		return append(out, r)
	}

	tables := parseOpenAPITables(root.body)
	capped := false
	if len(tables) > maxTables {
		tables = tables[:maxTables]
		capped = true
	}
	for _, tbl := range tables {
		rec := p.supabaseTable(ctx, tg, hdr, tbl)
		if rec != nil {
			out = append(out, *rec)
		}
	}
	if capped {
		r := base(tg)
		r.Finding = findReachable
		r.Severity = "info"
		r.Detail = "table list truncated at " + strconv.Itoa(maxTables)
		out = append(out, r)
	}
	return out
}

// supabaseTable sends a count-only probe: limit=0 returns zero rows, and the
// exact count is read from the Content-Range header. No row is ever fetched.
func (p *prober) supabaseTable(ctx context.Context, tg target, hdr map[string]string, table string) *EnumRecord {
	extra := map[string]string{"Prefer": "count=exact"}
	for k, v := range hdr {
		extra[k] = v
	}
	resp, err := p.get(ctx, tg.endpoint+"/rest/v1/"+neturl.PathEscape(table)+"?limit=0", extra)
	if err != nil {
		return nil
	}
	if resp.status != http.StatusOK {
		// 401/403/400 => RLS or policy blocks anon reads: the healthy case.
		return nil
	}
	rec := base(tg)
	rec.Finding = findAnonReadableTable
	rec.Severity = "high"
	rec.Object = table
	rec.Status = resp.status
	rec.Count = parseContentRangeCount(resp.header.Get("Content-Range"))
	if rec.Count > 0 {
		rec.Severity = "high"
		rec.Detail = "table readable without authentication (" + strconv.Itoa(rec.Count) + " rows)"
	} else {
		rec.Detail = "table readable without authentication (empty or count hidden)"
	}
	return &rec
}

func (p *prober) supabaseAuthSettings(ctx context.Context, tg target) (EnumRecord, bool) {
	extra := map[string]string{}
	if tg.key != "" {
		extra["apikey"] = tg.key
	}
	resp, err := p.get(ctx, tg.endpoint+"/auth/v1/settings", extra)
	if err != nil || resp.status != http.StatusOK {
		return EnumRecord{}, false
	}
	providers, signupDisabled := parseAuthSettings(resp.body)
	rec := base(tg)
	rec.Finding = findAuthSettings
	rec.Severity = "info"
	rec.Status = resp.status
	detail := "providers: " + strings.Join(providers, ",")
	if !signupDisabled {
		detail += "; signup enabled"
	}
	rec.Detail = detail
	return rec, true
}

// ---- Firebase RTDB --------------------------------------------------------

func (p *prober) enumFirebase(ctx context.Context, tg target) []EnumRecord {
	// Only a Realtime Database host exposes the .json REST surface; a plain
	// firebaseapp.com hosting URL does not, so it is only recorded as reachable.
	if !isRTDBHost(tg.host) {
		r := base(tg)
		r.Finding = findReachable
		r.Severity = "info"
		r.Detail = "firebase hosting/app endpoint (no RTDB REST surface)"
		return []EnumRecord{r}
	}

	// shallow=true returns only top-level key names (as booleans), never the
	// values behind them: a world-readable database is detected without
	// exfiltrating any of its contents.
	resp, err := p.get(ctx, tg.endpoint+"/.json?shallow=true&limitToFirst=1", nil)
	if err != nil {
		r := base(tg)
		r.Finding = findReachable
		r.Severity = "info"
		r.Detail = "RTDB not reachable"
		return []EnumRecord{r}
	}
	r := base(tg)
	r.Status = resp.status
	switch {
	case resp.status == http.StatusOK && looksReadable(resp.body):
		r.Finding = findPublicRTDB
		r.Severity = "high"
		r.Count = countTopLevelKeys(resp.body)
		r.Detail = "database root readable without authentication"
	case resp.status == http.StatusUnauthorized || resp.status == http.StatusForbidden:
		r.Finding = findLockedRTDB
		r.Severity = "info"
		r.Detail = "RTDB reachable but read is denied (rules enforced)"
	default:
		r.Finding = findLockedRTDB
		r.Severity = "info"
		r.Detail = "RTDB reachable; no public data at root"
	}
	return []EnumRecord{r}
}

// ---- Appwrite -------------------------------------------------------------

func (p *prober) enumAppwrite(ctx context.Context, tg target) []EnumRecord {
	resp, err := p.get(ctx, tg.endpoint+"/v1/health/version", nil)
	r := base(tg)
	r.Finding = findReachable
	r.Severity = "info"
	if err != nil || resp.status != http.StatusOK {
		if resp != nil {
			r.Status = resp.status
		}
		r.Detail = "appwrite endpoint not confirmed"
		return []EnumRecord{r}
	}
	r.Status = resp.status
	if v := parseVersion(resp.body); v != "" {
		r.Detail = "appwrite version " + v
	} else {
		r.Detail = "appwrite reachable"
	}
	return []EnumRecord{r}
}

// ---- PocketBase -----------------------------------------------------------

func (p *prober) enumPocketBase(ctx context.Context, tg target) []EnumRecord {
	var out []EnumRecord

	health, err := p.get(ctx, tg.endpoint+"/api/health", nil)
	r := base(tg)
	r.Finding = findReachable
	r.Severity = "info"
	if err == nil && health.status == http.StatusOK {
		r.Status = health.status
		r.Detail = "pocketbase reachable"
	} else {
		if health != nil {
			r.Status = health.status
		}
		r.Detail = "pocketbase health not confirmed"
	}
	out = append(out, r)

	// /api/collections is admin-only; a 200 without auth is a real misconfig.
	coll, err := p.get(ctx, tg.endpoint+"/api/collections?perPage=1", nil)
	if err == nil && coll.status == http.StatusOK {
		c := base(tg)
		c.Finding = findPocketBaseCollections
		c.Severity = "high"
		c.Status = coll.status
		c.Count = parsePocketBaseTotal(coll.body)
		c.Detail = "collections metadata listed without admin authentication"
		out = append(out, c)
	}
	return out
}

// ---- parsers (table-driven tested) ----------------------------------------

// parseOpenAPITables extracts table names from a PostgREST OpenAPI/Swagger
// document. PostgREST lists each exposed table under "definitions"; it falls
// back to the "/{table}" entries under "paths".
func parseOpenAPITables(body []byte) []string {
	var doc struct {
		Definitions map[string]json.RawMessage `json:"definitions"`
		Paths       map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	set := map[string]struct{}{}
	for name := range doc.Definitions {
		set[name] = struct{}{}
	}
	if len(set) == 0 {
		for path := range doc.Paths {
			name := strings.Trim(path, "/")
			if name == "" || strings.ContainsAny(name, "/{") {
				continue // skip "/" (the root) and RPC/parameterized paths
			}
			set[name] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// parseContentRangeCount reads the total from a PostgREST Content-Range header
// of the form "0-24/573" or "*/573". Returns -1 when the total is unknown ("*").
func parseContentRangeCount(h string) int {
	h = strings.TrimSpace(h)
	if h == "" {
		return -1
	}
	slash := strings.LastIndex(h, "/")
	if slash < 0 {
		return -1
	}
	total := strings.TrimSpace(h[slash+1:])
	if total == "" || total == "*" {
		return -1
	}
	n, err := strconv.Atoi(total)
	if err != nil {
		return -1
	}
	return n
}

// parseAuthSettings reads the enabled external providers and the signup flag
// from a GoTrue /auth/v1/settings document. It stores only provider names and
// the flag — never any secret.
func parseAuthSettings(body []byte) (providers []string, signupDisabled bool) {
	var doc struct {
		External      map[string]bool `json:"external"`
		DisableSignup bool            `json:"disable_signup"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, false
	}
	for name, enabled := range doc.External {
		if enabled {
			providers = append(providers, name)
		}
	}
	sort.Strings(providers)
	return providers, doc.DisableSignup
}

func parseVersion(body []byte) string {
	var doc struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return ""
	}
	return doc.Version
}

// parsePocketBaseTotal reads totalItems from a PocketBase list response's meta
// without retaining the items array.
func parsePocketBaseTotal(body []byte) int {
	var doc struct {
		TotalItems *int `json:"totalItems"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.TotalItems == nil {
		return -1
	}
	return *doc.TotalItems
}

// countTopLevelKeys counts the keys of a shallow RTDB response ({"k":true,...})
// without caring about values. A non-object (e.g. `true`) counts as 1.
func countTopLevelKeys(body []byte) int {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err == nil {
		return len(obj)
	}
	return 1
}

// looksReadable reports whether a shallow RTDB 200 body carries data (a
// non-empty object, or a scalar) rather than the JSON null of an empty/denied
// root.
func looksReadable(body []byte) bool {
	t := strings.TrimSpace(string(body))
	return t != "" && t != "null" && t != "{}"
}

func isRTDBHost(host string) bool {
	host = strings.ToLower(host)
	return strings.HasSuffix(host, ".firebaseio.com") || strings.HasSuffix(host, ".firebasedatabase.app")
}
