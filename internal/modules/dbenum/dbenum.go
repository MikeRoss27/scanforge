// Package dbenum performs ACTIVE, read-only enumeration of the backend-as-a-
// service providers that dbdetect found in the target's own client code. It
// consumes the db_fingerprint artifact and, for every backend host that is in
// the effective run scope, sends a small, bounded set of read-only probes:
//
//   - Supabase: the PostgREST OpenAPI root (table listing) and, per table, a
//     count-only probe (limit=0 + Prefer: count=exact) plus the public
//     /auth/v1/settings. It reads the Content-Range row count only — it never
//     requests or stores a single row of data.
//   - Firebase RTDB: a shallow probe (?shallow=true) that returns only the
//     top-level key names, never their values, so a world-readable database is
//     detected without exfiltrating it.
//   - Appwrite: the public health/version endpoints.
//   - PocketBase: the public health endpoint and the admin-only /api/collections
//     (a 200 there is a misconfiguration).
//
// Two invariants make this safe to ship in the default profiles:
//
//  1. Scope gate: a fingerprint host is probed only when runCtx.IsInScope says
//     so. dbdetect auto-scopes the exact backend hosts it discovered, so this
//     module touches the target's own infrastructure and nothing else.
//  2. Non-exfiltration: every probe is constructed to reveal existence,
//     permission and counts — never row/document contents — and the audit
//     artifact only ever stores those structural facts.
package dbenum

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/modules/dbcore"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

const (
	outputRel      = dbcore.OutputDir + "/db-enum.jsonl"
	requestTimeout = 20 * time.Second
	hostWorkers    = 6
	maxBodyBytes   = 1 << 20 // 1 MiB: an OpenAPI root can be large; rows are never fetched.
	maxTables      = 200
)

// EnumRecord is one line of db-enum.jsonl. It records a structural fact about a
// backend — reachability, an exposed object, a permission result or a count —
// and deliberately carries no row/document contents.
type EnumRecord struct {
	Host      string `json:"host"`
	Backend   string `json:"backend"`
	Endpoint  string `json:"endpoint"`
	Finding   string `json:"finding"`          // stable id, e.g. "anon-readable-table"
	Severity  string `json:"severity"`         // critical/high/medium/low/info
	Object    string `json:"object,omitempty"` // table / collection / provider name
	Count     int    `json:"count,omitempty"`  // row count when known; -1 when unknown
	Status    int    `json:"status,omitempty"` // HTTP status of the decisive probe
	Detail    string `json:"detail,omitempty"` // short human context, never row data
	ScannedAt string `json:"scanned_at,omitempty"`
}

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return "dbenum" }
func (m *Module) Description() string {
	return "Actively but read-only enumerates detected backends (Supabase REST/RLS, Firebase RTDB, Appwrite, PocketBase) for anon-readable tables, public databases and exposed collections"
}
func (m *Module) Requires() []string { return []string{"db_fingerprint"} }
func (m *Module) Produces() []string { return []string{"db_enum"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, _ runner.Executor) (*modules.Result, error) {
	art, err := runCtx.MustArtifact("db_fingerprint")
	if err != nil {
		return nil, err
	}
	records, err := dbcore.Load(runCtx.Run.Path(art.Path))
	if err != nil {
		return nil, fmt.Errorf("failed to load db fingerprint: %w", err)
	}

	// Collapse the fingerprint to one enumeration target per (host, backend),
	// keeping the most useful public key (an anon/publishable key lets the
	// Supabase REST root be read). Order is deterministic by host.
	targets := planTargets(records)

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, runner.Command{
		Name: "dbenum (native)",
		Args: []string{"-targets", strconv.Itoa(len(targets)), "-workers", strconv.Itoa(hostWorkers), "-mode", "read-only"},
	}); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	res := &modules.Result{
		Name:        m.Name(),
		Status:      "completed",
		OutputFiles: map[string]string{"db_enum": outputRel},
	}

	// A dry run records intent (the command log above) but sends nothing and
	// still publishes an empty, valid artifact for the DAG.
	if runCtx.DryRun {
		if werr := writeRecords(runCtx, nil); werr != nil {
			return nil, werr
		}
		return res, nil
	}

	// The hard gate: only probe hosts the effective scope allows. dbdetect
	// auto-scopes the exact backend hosts it discovered; a host that is not in
	// scope (e.g. a sibling project pulled in from third-party JS) is skipped
	// and never contacted.
	var inScope []target
	for _, tg := range targets {
		if runCtx.IsInScope(tg.host) {
			inScope = append(inScope, tg)
			continue
		}
		runCtx.EmitWarning(fmt.Sprintf("dbenum: %s (%s) is out of scope — not probed", tg.host, tg.backend))
	}

	if len(inScope) == 0 {
		if werr := writeRecords(runCtx, nil); werr != nil {
			return nil, werr
		}
		return modules.SkipNotApplicable(res, nil, "no in-scope backend to enumerate")
	}

	client, closeConn, err := modules.NewProxyClient(runCtx.Proxy, requestTimeout)
	if err != nil {
		return nil, err
	}
	defer closeConn()

	var (
		mu  sync.Mutex
		all []EnumRecord
		wg  sync.WaitGroup
	)
	sem := make(chan struct{}, hostWorkers)
	for _, tg := range inScope {
		wg.Add(1)
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Done()
			wg.Wait()
			return nil, ctx.Err()
		}
		go func(tg target) {
			defer wg.Done()
			defer func() { <-sem }()
			p := &prober{client: client, headers: runCtx.Headers}
			recs := p.enumerate(ctx, tg)
			mu.Lock()
			all = append(all, recs...)
			mu.Unlock()
		}(tg)
	}
	wg.Wait()

	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Host != all[j].Host {
			return all[i].Host < all[j].Host
		}
		if all[i].Finding != all[j].Finding {
			return all[i].Finding < all[j].Finding
		}
		return all[i].Object < all[j].Object
	})

	stamp := time.Now().UTC().Format(time.RFC3339)
	for i := range all {
		all[i].ScannedAt = stamp
	}

	// Surface exposures live, highest signal first is handled by the console;
	// here we just emit one finding per record that is worth an operator's eye.
	for _, rec := range all {
		if rec.Severity == "" || rec.Severity == "debug" {
			continue
		}
		runCtx.EmitFinding(modules.Finding{
			Module:   m.Name(),
			Severity: rec.Severity,
			Title:    findingTitle(rec),
			Target:   rec.Endpoint,
			Detail:   rec.Detail,
		})
	}

	if err := writeRecords(runCtx, all); err != nil {
		return nil, err
	}
	return res, nil
}

func writeRecords(runCtx *modules.RunContext, recs []EnumRecord) error {
	if err := saveEnum(runCtx.Run.Path(outputRel), recs); err != nil {
		return fmt.Errorf("failed to write db enum: %w", err)
	}
	if err := runCtx.AddArtifact("db_enum", modules.Artifact{
		Name: "db_enum",
		Type: "jsonl",
		Path: outputRel,
	}); err != nil {
		return fmt.Errorf("failed to publish db_enum: %w", err)
	}
	return nil
}

func findingTitle(rec EnumRecord) string {
	switch rec.Finding {
	case findAnonReadableTable:
		return "Supabase table readable with anon key"
	case findAuthSettings:
		return "Supabase auth settings exposed"
	case findSupabaseNeedsKey:
		return "Supabase project found (no anon key to enumerate)"
	case findPublicRTDB:
		return "Firebase Realtime Database is world-readable"
	case findLockedRTDB:
		return "Firebase Realtime Database reachable (locked)"
	case findPocketBaseCollections:
		return "PocketBase collections endpoint exposed"
	case findReachable:
		return fmt.Sprintf("%s backend reachable", titleCase(rec.Backend))
	default:
		return fmt.Sprintf("%s: %s", rec.Backend, rec.Finding)
	}
}

// target is one backend to enumerate: a host, its base endpoint, the backend
// kind and the best public key available for it (may be empty).
type target struct {
	host     string
	endpoint string
	backend  string
	key      string // public-by-design key only (never a secret)
}

// planTargets reduces the fingerprint records to one target per (host, backend),
// preferring a record that carries a usable public key.
func planTargets(records []dbcore.FingerprintRecord) []target {
	type key struct{ host, backend string }
	idx := map[key]*target{}
	var order []key
	for _, r := range records {
		if r.Host == "" || r.Endpoint == "" {
			continue
		}
		k := key{r.Host, r.Backend}
		tg, ok := idx[k]
		if !ok {
			tg = &target{host: r.Host, endpoint: strings.TrimRight(r.Endpoint, "/"), backend: r.Backend}
			idx[k] = tg
			order = append(order, k)
		}
		// Keep the first public key we see; dbcore only stores KeyValue for
		// public-by-design keys, so this never carries a secret.
		if tg.key == "" && r.KeyValue != "" {
			tg.key = r.KeyValue
		}
	}
	out := make([]target, 0, len(order))
	for _, k := range order {
		out = append(out, *idx[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].host != out[j].host {
			return out[i].host < out[j].host
		}
		return out[i].backend < out[j].backend
	})
	return out
}
