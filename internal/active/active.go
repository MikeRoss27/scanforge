// Package active is the single gate for every state-changing capability
// exposed to agents and the local API: planning (read-only), starting and
// stopping scans. Active actions are disabled by default, require an explicit
// scope file (strict --scope semantics, no implicit scope, no interactive
// confirmation) and a target inside it, and are audit-logged to JSONL.
package active

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/MikeRoss27/scanforge/internal/app"
	scanscope "github.com/MikeRoss27/scanforge/internal/scope"
)

// Sentinel errors.
var (
	ErrDisabled   = errors.New("active scanning is disabled (start the server with --allow-active and --scope <file>)")
	ErrOutOfScope = errors.New("target is not allowed by the explicit scope file")
	ErrInvalid    = errors.New("invalid argument")
	ErrBusy       = errors.New("too many concurrent scans")
	ErrUnknown    = errors.New("unknown scan")
)

var (
	targetRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.:/_\[\]-]{0,252}$`)
	profileRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
)

// Planner is the existing plan logic (app.App.Plan); it creates nothing.
type Planner func(app.PlanOptions) ([]*app.PlanResult, error)

// Config configures a Controller.
type Config struct {
	Allow         bool
	ScopeFile     string // mandatory when Allow
	AuditPath     string // JSONL, mandatory when Allow
	LogDir        string // scan stdout/stderr logs
	ConfigPath    string // forwarded as --config to child scans
	MaxConcurrent int
	Actor         string // "mcp" or "api"
}

// Controller owns the permission model and the audit log.
type Controller struct {
	cfg      Config
	launcher Launcher
	planner  Planner

	mu    sync.Mutex
	scans map[string]*scan
	audit sync.Mutex
}

// New validates cfg. With Allow set the scope file must load and allow at
// least one entry, and an audit path is required.
func New(cfg Config, launcher Launcher, planner Planner) (*Controller, error) {
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 2
	}
	if cfg.Actor == "" {
		cfg.Actor = "agent"
	}
	c := &Controller{cfg: cfg, launcher: launcher, planner: planner, scans: map[string]*scan{}}
	if cfg.Allow {
		if cfg.ScopeFile == "" {
			return nil, fmt.Errorf("%w: --allow-active requires an explicit --scope file", ErrInvalid)
		}
		sc, err := scanscope.LoadFromFile(cfg.ScopeFile)
		if err != nil {
			return nil, err
		}
		if len(sc.Entries()) == 0 {
			return nil, fmt.Errorf("%w: scope file %q has no entries", ErrInvalid, cfg.ScopeFile)
		}
		if cfg.AuditPath == "" {
			return nil, fmt.Errorf("%w: an audit log path is required in active mode", ErrInvalid)
		}
		abs, err := filepath.Abs(cfg.ScopeFile)
		if err != nil {
			return nil, err
		}
		c.cfg.ScopeFile = abs
		if c.cfg.AuditPath, err = filepath.Abs(cfg.AuditPath); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Allowed reports whether active tools are enabled.
func (c *Controller) Allowed() bool { return c.cfg.Allow }

// Audit is one JSONL record. It never carries credentials: the scan request
// type has no header/cookie/key fields at all.
type Audit struct {
	Time     string `json:"time"`
	Actor    string `json:"actor"`
	Action   string `json:"action"`
	Decision string `json:"decision"` // allowed | denied | error
	Reason   string `json:"reason,omitempty"`
	Target   string `json:"target,omitempty"`
	Profile  string `json:"profile,omitempty"`
	ScanID   string `json:"scan_id,omitempty"`
	PID      int    `json:"pid,omitempty"`
	Scope    string `json:"scope_file,omitempty"`
	DryRun   bool   `json:"dry_run,omitempty"`
}

func (c *Controller) log(a Audit) {
	a.Time = time.Now().UTC().Format(time.RFC3339Nano)
	a.Actor = c.cfg.Actor
	if c.cfg.AuditPath == "" {
		return
	}
	c.audit.Lock()
	defer c.audit.Unlock()
	if err := os.MkdirAll(filepath.Dir(c.cfg.AuditPath), 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(c.cfg.AuditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	data, _ := json.Marshal(a)
	_, _ = f.Write(append(data, '\n'))
}

// StartRequest deliberately has no header, cookie, proxy or key fields.
type StartRequest struct {
	Target  string
	Profile string
	DryRun  bool
}

// ScanInfo describes a scan started by this server.
type ScanInfo struct {
	ScanID    string `json:"scan_id"`
	Target    string `json:"target"`
	Profile   string `json:"profile"`
	PID       int    `json:"pid"`
	DryRun    bool   `json:"dry_run,omitempty"`
	StartedAt string `json:"started_at"`
	Status    string `json:"status"` // running | exited | stopped
	Error     string `json:"error,omitempty"`
	LogFile   string `json:"log_file,omitempty"`
}

type scan struct {
	info    ScanInfo
	proc    Proc
	stopped bool
}

// ValidTarget checks the target syntax (before any scope check).
func ValidTarget(target string) error {
	if !targetRE.MatchString(target) {
		return fmt.Errorf("%w: target %q", ErrInvalid, target)
	}
	return nil
}

func (c *Controller) deny(action string, req StartRequest, err error) error {
	d := "denied"
	if !errors.Is(err, ErrDisabled) && !errors.Is(err, ErrOutOfScope) && !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrBusy) {
		d = "error"
	}
	c.log(Audit{Action: action, Decision: d, Reason: err.Error(), Target: req.Target, Profile: req.Profile, Scope: c.cfg.ScopeFile, DryRun: req.DryRun})
	return err
}

// Start launches `scanforge run` as a child process with the explicit scope
// file. The child enforces the same scope again on its own.
func (c *Controller) Start(req StartRequest) (*ScanInfo, error) {
	const action = "start_authorized_scan"
	if !c.cfg.Allow {
		return nil, c.deny(action, req, ErrDisabled)
	}
	if err := ValidTarget(req.Target); err != nil {
		return nil, c.deny(action, req, err)
	}
	if req.Profile == "" {
		req.Profile = "safe"
	}
	if !profileRE.MatchString(req.Profile) {
		return nil, c.deny(action, req, fmt.Errorf("%w: profile %q", ErrInvalid, req.Profile))
	}
	// Re-read the scope file on every start so the file stays the authority.
	sc, err := scanscope.LoadFromFile(c.cfg.ScopeFile)
	if err != nil {
		return nil, c.deny(action, req, err)
	}
	if !sc.IsAllowed(req.Target) {
		return nil, c.deny(action, req, fmt.Errorf("%w: %q", ErrOutOfScope, req.Target))
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	running := 0
	for _, s := range c.scans {
		if s.info.Status == "running" {
			running++
		}
	}
	if running >= c.cfg.MaxConcurrent {
		return nil, c.deny(action, req, ErrBusy)
	}

	id := newID()
	args := []string{}
	if c.cfg.ConfigPath != "" {
		args = append(args, "--config", c.cfg.ConfigPath)
	}
	args = append(args, "run", "--scope", c.cfg.ScopeFile, "--profile", req.Profile)
	if req.DryRun {
		args = append(args, "--dry-run")
	}
	args = append(args, "--", req.Target)

	logFile := ""
	if c.cfg.LogDir != "" {
		if err := os.MkdirAll(c.cfg.LogDir, 0o700); err == nil {
			logFile = filepath.Join(c.cfg.LogDir, "scan-"+id+".log")
		}
	}
	proc, err := c.launcher.Start(args, logFile)
	if err != nil {
		return nil, c.deny(action, req, fmt.Errorf("launch scan: %w", err))
	}
	s := &scan{
		proc: proc,
		info: ScanInfo{
			ScanID: id, Target: req.Target, Profile: req.Profile, PID: proc.PID(), DryRun: req.DryRun,
			StartedAt: time.Now().UTC().Format(time.RFC3339), Status: "running", LogFile: logFile,
		},
	}
	c.scans[id] = s
	go func() {
		werr := proc.Wait()
		c.mu.Lock()
		defer c.mu.Unlock()
		s.info.Status = "exited"
		if s.stopped {
			s.info.Status = "stopped"
		}
		if werr != nil {
			s.info.Error = werr.Error()
		}
	}()
	c.log(Audit{Action: action, Decision: "allowed", Target: req.Target, Profile: req.Profile, ScanID: id, PID: s.info.PID, Scope: c.cfg.ScopeFile, DryRun: req.DryRun})
	info := s.info
	return &info, nil
}

// Stop interrupts a scan started by this server (SIGINT so the run finalizes
// its manifest), then kills it if it has not exited after a grace period.
func (c *Controller) Stop(scanID string) (*ScanInfo, error) {
	const action = "stop_scan"
	if !c.cfg.Allow {
		return nil, c.deny(action, StartRequest{}, ErrDisabled)
	}
	c.mu.Lock()
	s, ok := c.scans[scanID]
	if !ok {
		c.mu.Unlock()
		c.log(Audit{Action: action, Decision: "denied", Reason: ErrUnknown.Error(), ScanID: scanID})
		return nil, fmt.Errorf("%w: %q", ErrUnknown, scanID)
	}
	if s.info.Status == "running" {
		s.stopped = true
		_ = s.proc.Interrupt()
		go func(p Proc, grace time.Duration) {
			time.Sleep(grace)
			c.mu.Lock()
			still := s.info.Status == "running"
			c.mu.Unlock()
			if still {
				_ = p.Kill()
			}
		}(s.proc, 15*time.Second)
	}
	info := s.info
	c.mu.Unlock()
	c.log(Audit{Action: action, Decision: "allowed", Target: info.Target, Profile: info.Profile, ScanID: scanID, PID: info.PID})
	return &info, nil
}

// Scans lists scans started by this server instance.
func (c *Controller) Scans() []ScanInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []ScanInfo{}
	for _, s := range c.scans {
		out = append(out, s.info)
	}
	return out
}

func newID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
