// Package runindex is a read-only reader over the file-based run store
// (runs/<target>/<timestamp>/). It is shared by the local HTTP API and the MCP
// server so both expose exactly the same view of past runs.
//
// Finding values are returned exactly as found on the target (they are bounty
// evidence). Only the operator's own credentials are scrubbed, see Scrubber.
package runindex

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/finding"
	"github.com/MikeRoss27/scanforge/internal/report"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

// Errors callers can map to protocol-level failures.
var (
	ErrInvalidRunID = errors.New("invalid run id")
	ErrNotFound     = errors.New("not found")
	ErrInvalidPath  = errors.New("invalid evidence path")
)

var segmentRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)

// evidenceDirs are the only run subdirectories whose files may be served.
// 00_meta is excluded on purpose: commands.log holds full command lines.
var evidenceDirs = map[string]bool{
	"01_subdomains": true, "02_http": true, "03_ports": true,
	"04_web": true, "05_content": true, "06_vulns": true,
}

var evidenceExts = map[string]bool{
	".json": true, ".jsonl": true, ".txt": true, ".xml": true, ".md": true,
	".csv": true, ".log": true, ".html": true, ".gnmap": true, ".nmap": true,
}

const (
	defaultEvidenceBytes = 256 << 10
	maxEvidenceBytes     = 1 << 20
)

// Index reads runs under Workspace.
type Index struct {
	Workspace string
	scrub     *Scrubber
}

// New returns an Index. operatorSecrets are credentials of the operator that
// must never appear in output (API keys, tokens...).
func New(workspace string, operatorSecrets ...string) *Index {
	return &Index{Workspace: workspace, scrub: NewScrubber(operatorSecrets...)}
}

// RunSummary is the list view of a run.
type RunSummary struct {
	RunID       string `json:"run_id"`
	Target      string `json:"target"`
	Profile     string `json:"profile,omitempty"`
	Status      string `json:"status"`
	StartedAt   string `json:"started_at,omitempty"`
	CompletedAt string `json:"completed_at,omitempty"`
	ScopeSource string `json:"scope_source,omitempty"`
	ScopeMode   string `json:"scope_mode,omitempty"`
}

// RunDetail is the single-run view.
type RunDetail struct {
	RunSummary
	Modules       []storage.ModuleResult `json:"modules,omitempty"`
	HasReport     bool                   `json:"has_report"`
	AssetCount    int                    `json:"asset_count"`
	FindingCount  int                    `json:"finding_count"`
	BySeverity    map[string]int         `json:"findings_by_severity,omitempty"`
	EvidenceFiles []string               `json:"evidence_files,omitempty"`
}

// FindingFilter narrows Findings. Empty fields match everything.
type FindingFilter struct {
	Severity string // exact normalized severity
	Asset    string // substring of asset name
	Source   string
	Kind     string
	Limit    int
	Offset   int
}

// FindingPage is a page of findings.
type FindingPage struct {
	RunID    string            `json:"run_id"`
	Total    int               `json:"total"`
	Findings []finding.Finding `json:"findings"`
}

// AssetPage is a page of assets.
type AssetPage struct {
	RunID  string          `json:"run_id"`
	Total  int             `json:"total"`
	Assets []*report.Asset `json:"assets"`
}

// Evidence is the evidence view for one finding or one raw artifact file.
type Evidence struct {
	RunID     string           `json:"run_id"`
	Finding   *finding.Finding `json:"finding,omitempty"`
	File      string           `json:"file,omitempty"`
	Offset    int64            `json:"offset,omitempty"`
	Content   string           `json:"content,omitempty"`
	Truncated bool             `json:"truncated,omitempty"`
	Files     []string         `json:"files,omitempty"`
}

// ParseRunID validates "<target-dir>/<timestamp>" and rejects anything that
// could escape the workspace.
func ParseRunID(id string) (target, stamp string, err error) {
	parts := strings.Split(id, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("%w: expected <target>/<timestamp>", ErrInvalidRunID)
	}
	for _, p := range parts {
		if !segmentRE.MatchString(p) || strings.Contains(p, "..") {
			return "", "", fmt.Errorf("%w: bad path segment", ErrInvalidRunID)
		}
	}
	return parts[0], parts[1], nil
}

// runDir resolves a run id to a directory strictly inside the workspace.
func (x *Index) runDir(id string) (string, error) {
	target, stamp, err := ParseRunID(id)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(x.Workspace, target, stamp)
	if err := x.within(dir, x.Workspace); err != nil {
		return "", err
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return "", fmt.Errorf("%w: run %q", ErrNotFound, id)
	}
	return dir, nil
}

// within verifies, after symlink resolution, that path is inside root.
func (x *Index) within(path, root string) error {
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("%w: workspace %q", ErrNotFound, root)
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", ErrNotFound, filepath.Base(path))
		}
		return err
	}
	rel, err := filepath.Rel(rootReal, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: path escapes the run store", ErrInvalidRunID)
	}
	return nil
}

func readManifest(dir string) (*storage.RunManifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, storage.ManifestRelPath))
	if err != nil {
		return nil, err
	}
	var m storage.RunManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func summarize(id string, m *storage.RunManifest) RunSummary {
	return RunSummary{
		RunID: id, Target: m.Target, Profile: m.Profile, Status: m.Status,
		StartedAt: m.StartedAt, CompletedAt: m.CompletedAt,
		ScopeSource: m.ScopeSource, ScopeMode: m.ScopeMode,
	}
}

// ListRuns returns runs newest first, optionally filtered by a substring of
// the target. limit <= 0 means 100.
func (x *Index) ListRuns(targetFilter string, limit int) ([]RunSummary, error) {
	if limit <= 0 {
		limit = 100
	}
	targets, err := os.ReadDir(x.Workspace)
	if err != nil {
		if os.IsNotExist(err) {
			return []RunSummary{}, nil
		}
		return nil, err
	}
	out := []RunSummary{}
	for _, t := range targets {
		if !t.IsDir() || !segmentRE.MatchString(t.Name()) {
			continue
		}
		stamps, err := os.ReadDir(filepath.Join(x.Workspace, t.Name()))
		if err != nil {
			continue
		}
		for _, s := range stamps {
			if !s.IsDir() || !segmentRE.MatchString(s.Name()) {
				continue
			}
			id := t.Name() + "/" + s.Name()
			dir, err := x.runDir(id)
			if err != nil {
				continue
			}
			m, err := readManifest(dir)
			if err != nil {
				continue
			}
			if targetFilter != "" && !strings.Contains(strings.ToLower(m.Target+" "+t.Name()), strings.ToLower(targetFilter)) {
				continue
			}
			out = append(out, summarize(id, m))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].StartedAt != out[j].StartedAt {
			return out[i].StartedAt > out[j].StartedAt
		}
		return out[i].RunID > out[j].RunID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// GetRun returns the detail view of one run.
func (x *Index) GetRun(id string) (*RunDetail, error) {
	dir, err := x.runDir(id)
	if err != nil {
		return nil, err
	}
	m, err := readManifest(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: manifest of %q", ErrNotFound, id)
	}
	d := &RunDetail{RunSummary: summarize(id, m), Modules: m.Modules}
	if rep, err := report.LoadFromFile(filepath.Join(dir, "report.json")); err == nil {
		d.HasReport = true
		d.AssetCount = len(rep.Assets)
		fs := finding.FromReport(rep)
		d.FindingCount = len(fs)
		d.BySeverity = map[string]int{}
		for _, f := range fs {
			d.BySeverity[string(f.Severity)]++
		}
	}
	d.EvidenceFiles, _ = x.listEvidence(dir)
	return d, nil
}

func (x *Index) loadReport(id string) (*report.Report, string, error) {
	dir, err := x.runDir(id)
	if err != nil {
		return nil, "", err
	}
	rep, err := report.LoadFromFile(filepath.Join(dir, "report.json"))
	if err != nil {
		return nil, dir, fmt.Errorf("%w: report.json of %q", ErrNotFound, id)
	}
	return rep, dir, nil
}

// Assets returns the assets of a run, sorted by name.
func (x *Index) Assets(id, nameFilter string, limit, offset int) (*AssetPage, error) {
	rep, _, err := x.loadReport(id)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(rep.Assets))
	for n := range rep.Assets {
		if nameFilter == "" || strings.Contains(strings.ToLower(n), strings.ToLower(nameFilter)) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	page := &AssetPage{RunID: id, Total: len(names), Assets: []*report.Asset{}}
	lo, hi := window(len(names), limit, offset)
	for _, n := range names[lo:hi] {
		page.Assets = append(page.Assets, rep.Assets[n])
	}
	return page, nil
}

var severityRank = map[finding.Severity]int{
	finding.SevCritical: 5, finding.SevHigh: 4, finding.SevMedium: 3, finding.SevLow: 2, finding.SevInfo: 1,
}

// Findings returns findings, most severe first. Values (including leaked
// secrets) are NOT masked.
func (x *Index) Findings(id string, f FindingFilter) (*FindingPage, error) {
	rep, _, err := x.loadReport(id)
	if err != nil {
		return nil, err
	}
	all := finding.FromReport(rep)
	sev := finding.Severity("")
	if f.Severity != "" {
		sev = finding.NormalizeSeverity(f.Severity)
	}
	var kept []finding.Finding
	for _, it := range all {
		if sev != "" && it.Severity != sev {
			continue
		}
		if f.Asset != "" && !strings.Contains(strings.ToLower(it.Asset), strings.ToLower(f.Asset)) {
			continue
		}
		if f.Source != "" && !strings.EqualFold(it.Source, f.Source) {
			continue
		}
		if f.Kind != "" && !strings.EqualFold(it.Kind, f.Kind) {
			continue
		}
		kept = append(kept, it)
	}
	sort.SliceStable(kept, func(i, j int) bool { return severityRank[kept[i].Severity] > severityRank[kept[j].Severity] })
	page := &FindingPage{RunID: id, Total: len(kept), Findings: []finding.Finding{}}
	lo, hi := window(len(kept), f.Limit, f.Offset)
	page.Findings = append(page.Findings, kept[lo:hi]...)
	return page, nil
}

// Evidence returns, depending on the arguments: one finding's evidence
// (findingID), a raw artifact file slice (file), or the list of artifact files.
func (x *Index) Evidence(id, findingID, file string, offset int64, maxBytes int) (*Evidence, error) {
	dir, err := x.runDir(id)
	if err != nil {
		return nil, err
	}
	ev := &Evidence{RunID: id}
	switch {
	case findingID != "":
		rep, _, err := x.loadReport(id)
		if err != nil {
			return nil, err
		}
		for _, it := range finding.FromReport(rep) {
			if string(it.ID) == findingID {
				it := it
				ev.Finding = &it
				return ev, nil
			}
		}
		return nil, fmt.Errorf("%w: finding %q", ErrNotFound, findingID)
	case file != "":
		return x.readEvidenceFile(dir, ev, file, offset, maxBytes)
	default:
		ev.Files, err = x.listEvidence(dir)
		return ev, err
	}
}

func (x *Index) readEvidenceFile(dir string, ev *Evidence, file string, offset int64, maxBytes int) (*Evidence, error) {
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(file)))
	parts := strings.Split(clean, "/")
	if filepath.IsAbs(file) || strings.Contains(file, "\\") || strings.Contains(file, "\x00") ||
		len(parts) < 2 || !evidenceDirs[parts[0]] || !evidenceExts[strings.ToLower(filepath.Ext(clean))] {
		return nil, ErrInvalidPath
	}
	for _, p := range parts {
		if p == ".." || p == "." || p == "" {
			return nil, ErrInvalidPath
		}
	}
	full := filepath.Join(dir, filepath.FromSlash(clean))
	if err := x.within(full, dir); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, err
		}
		return nil, ErrInvalidPath
	}
	info, err := os.Stat(full)
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: file %q", ErrNotFound, clean)
	}
	if maxBytes <= 0 {
		maxBytes = defaultEvidenceBytes
	}
	if maxBytes > maxEvidenceBytes {
		maxBytes = maxEvidenceBytes
	}
	if offset < 0 {
		offset = 0
	}
	f, err := os.Open(full)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBytes {
		data = data[:maxBytes]
		ev.Truncated = true
	}
	ev.File, ev.Offset, ev.Content = clean, offset, string(data)
	return ev, nil
}

func (x *Index) listEvidence(dir string) ([]string, error) {
	var files []string
	for d := range evidenceDirs {
		root := filepath.Join(dir, d)
		_ = filepath.WalkDir(root, func(p string, e os.DirEntry, err error) error {
			if err != nil || e.IsDir() || !e.Type().IsRegular() {
				return nil
			}
			if !evidenceExts[strings.ToLower(filepath.Ext(p))] {
				return nil
			}
			if rel, err := filepath.Rel(dir, p); err == nil {
				files = append(files, filepath.ToSlash(rel))
			}
			return nil
		})
	}
	sort.Strings(files)
	return files, nil
}

// ScrubberFor returns the scrubber for a run: the static operator secrets plus
// the header/proxy credentials recorded in that run's commands.log.
func (x *Index) ScrubberFor(id string) *Scrubber {
	s := x.scrub.Clone()
	if id == "" {
		return s
	}
	if dir, err := x.runDir(id); err == nil {
		s.Add(secretsFromCommandLog(filepath.Join(dir, "00_meta", "commands.log"))...)
	}
	return s
}

// Encode marshals v as JSON with the operator's credentials masked. runID
// (optional) adds that run's own recorded credentials to the mask.
func (x *Index) Encode(v any, runID string) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return []byte(x.ScrubberFor(runID).Apply(string(data))), nil
}

func window(n, limit, offset int) (int, int) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	if offset > n {
		offset = n
	}
	hi := offset + limit
	if hi > n {
		hi = n
	}
	return offset, hi
}
