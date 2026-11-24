// Package assets keeps a file-based, append-only history of the assets seen
// for a target across runs (runs/<target>/assets.jsonl). It powers
// `scanforge run --incremental` and `scanforge assets`: every completed run
// appends one "run" record plus one record per asset (new, unchanged,
// changed) and per asset that disappeared (gone). There is no database; the
// current state of an asset is its last line.
package assets

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/report"
	"github.com/MikeRoss27/scanforge/internal/scope"
)

// FileName is the history file, stored next to the run directories.
const FileName = "assets.jsonl"

// Asset types recorded in the history.
const (
	TypeSubdomain = "subdomain"
	TypeHost      = "host" // a bare IP address used as the asset name
	TypeURL       = "url"  // an HTTP service probed by httpx
	TypePath      = "path" // a path found by katana / ffuf
	TypePort      = "port"
	TypeTech      = "tech"
	TypeFinding   = "finding"
	// TypeRun is the per-run bookkeeping record (scope hash, tool versions);
	// it is not an asset.
	TypeRun = "run"
)

// Asset statuses.
const (
	StatusNew       = "new"
	StatusUnchanged = "unchanged"
	StatusChanged   = "changed"
	StatusGone      = "gone"
)

// Record is one line of assets.jsonl.
type Record struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	LastRunID string `json:"last_run_id"`
	Status    string `json:"status"`
	// Host is the string checked against the effective scope before the
	// record is ever reused; records without one are never reused.
	Host string `json:"host,omitempty"`
	// Fingerprint digests the attributes whose change makes an asset
	// "changed" (HTTP status/title/server, service version, IPs...).
	Fingerprint string `json:"fingerprint,omitempty"`
	// ScopeSHA256 and ToolVersions are only set on TypeRun records and drive
	// the cache invalidation.
	ScopeSHA256  string            `json:"scope_sha256,omitempty"`
	ToolVersions map[string]string `json:"tool_versions,omitempty"`
}

// Observation is an asset present in a finished run's consolidated report.
type Observation struct {
	Type        string
	Value       string
	Host        string
	Fingerprint string
}

// History is the in-memory state rebuilt from assets.jsonl.
type History struct {
	// Records holds the latest record of every asset (last line wins).
	Records map[string]Record
	// Last is the most recent run record, nil when no run was recorded.
	Last *Record
	runs map[string]bool
}

func key(typ, value string) string { return typ + "\x00" + value }

// PathFor returns the history file of a target, given any of its run
// directories (runs/<target>/<id>).
func PathFor(runRoot string) string {
	return filepath.Join(filepath.Dir(runRoot), FileName)
}

// Load reads the history. A missing file is an empty history; malformed
// lines are skipped so one corrupt line never disables incremental mode.
func Load(path string) (*History, error) {
	h := &History{Records: map[string]Record{}, runs: map[string]bool{}}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return h, nil
		}
		return nil, fmt.Errorf("open asset history: %w", err)
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec Record
		if json.Unmarshal(line, &rec) != nil || rec.Type == "" || rec.Value == "" {
			continue
		}
		if rec.Type == TypeRun {
			r := rec
			h.Last = &r
			h.runs[rec.Value] = true
			continue
		}
		h.Records[key(rec.Type, rec.Value)] = rec
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read asset history: %w", err)
	}
	return h, nil
}

// HasRun reports whether the run was already recorded (makes updates
// idempotent, e.g. when a finished run is resumed).
func (h *History) HasRun(runID string) bool { return h.runs[runID] }

// Lookup returns the latest record of an asset.
func (h *History) Lookup(typ, value string) (Record, bool) {
	rec, ok := h.Records[key(typ, value)]
	return rec, ok
}

// FilterScope drops every record that is not allowed by the current scope
// (or that carries no scope key at all) and returns how many were dropped.
// It must run before a history is used to steer a scan: the history may have
// been written under a wider scope. A nil scope keeps everything.
func (h *History) FilterScope(sc *scope.Scope) int {
	if sc == nil {
		return 0
	}
	dropped := 0
	for k, rec := range h.Records {
		if rec.Host == "" || !sc.IsAllowed(rec.Host) {
			delete(h.Records, k)
			dropped++
		}
	}
	return dropped
}

// Sorted returns the latest records ordered by type then value.
func (h *History) Sorted() []Record {
	out := make([]Record, 0, len(h.Records))
	for _, rec := range h.Records {
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// Invalidated reports whether the cache must be ignored: the scope hash or
// the version of a tool present on both sides differs from the last
// recorded run. Without a previous run there is nothing to invalidate.
func (h *History) Invalidated(scopeSHA string, versions map[string]string) bool {
	if h.Last == nil {
		return false
	}
	if h.Last.ScopeSHA256 != scopeSHA {
		return true
	}
	for name, v := range versions {
		if old, ok := h.Last.ToolVersions[name]; ok && old != v {
			return true
		}
	}
	return false
}

// Observe flattens a consolidated report into observations, reusing the
// report model rather than re-parsing tool output.
func Observe(rep *report.Report) []Observation {
	if rep == nil {
		return nil
	}
	seen := map[string]int{}
	var out []Observation
	add := func(o Observation) {
		if o.Value == "" {
			return
		}
		k := key(o.Type, o.Value)
		if i, ok := seen[k]; ok {
			out[i] = o
			return
		}
		seen[k] = len(out)
		out = append(out, o)
	}
	for name, asset := range rep.Assets {
		typ := TypeSubdomain
		if net.ParseIP(name) != nil {
			typ = TypeHost
		}
		ips := append([]string(nil), asset.IPs...)
		ips = append(ips, asset.CNAMEs...)
		sort.Strings(ips)
		add(Observation{Type: typ, Value: name, Host: name, Fingerprint: strings.Join(ips, ",")})
		for _, svc := range asset.HTTP {
			add(Observation{Type: TypeURL, Value: svc.URL, Host: svc.URL, Fingerprint: HTTPFingerprint(svc)})
		}
		for _, p := range asset.Paths {
			fp := ""
			if p.StatusCode > 0 {
				fp = strconv.Itoa(p.StatusCode)
			}
			add(Observation{Type: TypePath, Value: p.URL, Host: p.URL, Fingerprint: fp})
		}
		for _, port := range asset.Ports {
			proto := port.Protocol
			if proto == "" {
				proto = "tcp"
			}
			add(Observation{
				Type: TypePort, Value: fmt.Sprintf("%s:%d/%s", name, port.Number, proto), Host: name,
				Fingerprint: strings.Join([]string{port.Service, port.Product, port.Version}, "|"),
			})
		}
		for _, tech := range asset.Technologies {
			add(Observation{Type: TypeTech, Value: name + "|" + tech, Host: name})
		}
		for _, v := range asset.Vulnerabilities {
			host := v.MatchedAt
			if host == "" {
				host = name
			}
			add(Observation{
				Type:        TypeFinding,
				Value:       strings.Join([]string{v.Source, v.TemplateID, v.Title, v.MatchedAt}, "|"),
				Host:        host,
				Fingerprint: v.Severity,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// HTTPFingerprint digests the stable attributes of an HTTP service.
// Content length and response time are volatile and deliberately excluded.
func HTTPFingerprint(svc report.HTTPService) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		strconv.Itoa(svc.StatusCode), svc.Title, svc.WebServer, svc.Location, svc.ContentType, svc.Favicon,
	}, "\x00")))
	return hex.EncodeToString(sum[:8])
}

// RunMeta describes the run whose observations are being recorded.
type RunMeta struct {
	RunID        string
	At           time.Time
	ScopeSHA256  string
	ToolVersions map[string]string
	// Coverage lists the asset types this run could actually observe; only
	// those can be marked gone.
	Coverage map[string]bool
	// Invalidated marks every observed asset as new (cache invalidation).
	Invalidated bool
}

// Coverage derives which asset types a run is able to declare "gone" from
// the modules that completed. When focused is true (incremental run whose
// expensive modules only looked at new/changed URLs) paths and findings are
// partial and therefore not covered.
func Coverage(completed map[string]bool, focused bool) map[string]bool {
	has := func(names ...string) bool {
		for _, n := range names {
			if completed[n] {
				return true
			}
		}
		return false
	}
	return map[string]bool{
		TypeSubdomain: has("subfinder", "dnsx", "httpx"),
		TypeHost:      has("subfinder", "dnsx", "httpx"),
		TypeURL:       has("httpx"),
		TypePort:      has("naabu", "nmap"),
		TypeTech:      has("httpx", "whatweb"),
		TypePath:      !focused && has("katana", "ffuf"),
		TypeFinding:   !focused && has("nuclei"),
	}
}

// Reconcile compares observations to the (scope-filtered) history and
// returns the records to append: a run record, one record per observed asset
// and one "gone" record per covered asset that is no longer observed.
func Reconcile(h *History, obs []Observation, meta RunMeta) []Record {
	now := meta.At.UTC().Format(time.RFC3339)
	recs := []Record{{
		Type: TypeRun, Value: meta.RunID, FirstSeen: now, LastSeen: now, LastRunID: meta.RunID,
		Status: "recorded", ScopeSHA256: meta.ScopeSHA256, ToolVersions: meta.ToolVersions,
	}}
	observed := make(map[string]bool, len(obs))
	for _, o := range obs {
		observed[key(o.Type, o.Value)] = true
		rec := Record{
			Type: o.Type, Value: o.Value, Host: o.Host, Fingerprint: o.Fingerprint,
			FirstSeen: now, LastSeen: now, LastRunID: meta.RunID, Status: StatusNew,
		}
		if prev, ok := h.Lookup(o.Type, o.Value); ok {
			rec.FirstSeen = prev.FirstSeen
			switch {
			case meta.Invalidated, prev.Status == StatusGone:
				rec.Status = StatusNew
			case prev.Fingerprint != o.Fingerprint:
				rec.Status = StatusChanged
			default:
				rec.Status = StatusUnchanged
			}
		}
		recs = append(recs, rec)
	}
	for _, prev := range h.Sorted() {
		if observed[key(prev.Type, prev.Value)] || prev.Status == StatusGone || !meta.Coverage[prev.Type] {
			continue
		}
		prev.Status = StatusGone
		prev.LastRunID = meta.RunID
		recs = append(recs, prev)
	}
	return recs
}

// Append adds records to the history atomically: the new file (old content
// plus the new lines) is written to a temporary file and renamed over the
// original, so a crash never leaves a truncated history.
func Append(path string, recs []Record) error {
	if len(recs) == 0 {
		return nil
	}
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read asset history: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create history dir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".assets-*")
	if err != nil {
		return fmt.Errorf("create temp history: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	var buf bytes.Buffer
	buf.Write(existing)
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		buf.WriteByte('\n')
	}
	for _, rec := range recs {
		line, err := json.Marshal(rec)
		if err != nil {
			_ = tmp.Close()
			return fmt.Errorf("encode asset record: %w", err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write asset history: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync asset history: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace asset history: %w", err)
	}
	return nil
}
