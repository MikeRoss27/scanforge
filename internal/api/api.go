// Package api serves a local HTTP JSON API over the file-based run store.
// GET endpoints are read-only; every other endpoint requires a bearer token
// generated at startup. It binds loopback only unless explicitly overridden.
package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/active"
	"github.com/MikeRoss27/scanforge/internal/runindex"
)

// Server is the HTTP API.
type Server struct {
	Index  *runindex.Index
	Active *active.Controller
	token  string
	remote bool
}

// NewToken returns a fresh random bearer token.
func NewToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// New builds a Server with the given bearer token (use NewToken()).
func New(idx *runindex.Index, ctl *active.Controller, token string) *Server {
	return &Server{Index: idx, Active: ctl, token: token}
}

// AllowRemoteHosts disables the loopback Host-header check (non-default).
func (s *Server) AllowRemoteHosts() { s.remote = true }

// CheckListenAddr refuses non-loopback binds unless allowRemote is set.
func CheckListenAddr(addr string, allowRemote bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", addr, err)
	}
	if allowRemote || isLoopbackHost(host) {
		return nil
	}
	return fmt.Errorf("refusing to bind %q: only loopback addresses are allowed (127.0.0.1 by default)", addr)
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Handler returns the routed handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		s.write(w, 200, map[string]any{"status": "ok", "active_mode": s.Active.Allowed()}, "")
	})
	mux.HandleFunc("GET /v1/runs", s.listRuns)
	mux.HandleFunc("GET /v1/runs/{target}/{stamp}", s.getRun)
	mux.HandleFunc("GET /v1/runs/{target}/{stamp}/assets", s.getAssets)
	mux.HandleFunc("GET /v1/runs/{target}/{stamp}/findings", s.getFindings)
	mux.HandleFunc("GET /v1/runs/{target}/{stamp}/evidence", s.getEvidence)
	mux.HandleFunc("POST /v1/plan", s.auth(s.plan))
	mux.HandleFunc("POST /v1/scans", s.auth(s.startScan))
	mux.HandleFunc("GET /v1/scans", s.auth(s.listScans))
	mux.HandleFunc("DELETE /v1/scans/{id}", s.auth(s.stopScan))
	return s.hostGuard(mux)
}

// hostGuard blocks DNS-rebinding: a browser page on another origin resolving
// to 127.0.0.1 would still send its own Host header.
func (s *Server) hostGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		if !isLoopbackHost(host) && !s.remote {
			s.fail(w, 403, "forbidden host")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if s.token == "" || got == r.Header.Get("Authorization") ||
			subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="scanforge"`)
			s.fail(w, 401, "missing or invalid bearer token")
			return
		}
		next(w, r)
	}
}

func (s *Server) runID(r *http.Request) string {
	return r.PathValue("target") + "/" + r.PathValue("stamp")
}

func (s *Server) write(w http.ResponseWriter, code int, v any, runID string) {
	data, err := s.Index.Encode(v, runID)
	if err != nil {
		http.Error(w, `{"error":"encode failed"}`, 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_, _ = w.Write(append(data, '\n'))
}

func (s *Server) fail(w http.ResponseWriter, code int, msg string) {
	s.write(w, code, map[string]string{"error": msg}, "")
}

func (s *Server) failErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, runindex.ErrInvalidRunID), errors.Is(err, runindex.ErrInvalidPath), errors.Is(err, active.ErrInvalid):
		s.fail(w, 400, err.Error())
	case errors.Is(err, runindex.ErrNotFound), errors.Is(err, active.ErrUnknown):
		s.fail(w, 404, err.Error())
	case errors.Is(err, active.ErrDisabled), errors.Is(err, active.ErrOutOfScope):
		s.fail(w, 403, err.Error())
	case errors.Is(err, active.ErrBusy):
		s.fail(w, 429, err.Error())
	default:
		s.fail(w, 500, err.Error())
	}
}

func intQ(r *http.Request, key string) int {
	n, _ := strconv.Atoi(r.URL.Query().Get(key))
	return n
}

func (s *Server) listRuns(w http.ResponseWriter, r *http.Request) {
	runs, err := s.Index.ListRuns(r.URL.Query().Get("target"), intQ(r, "limit"))
	if err != nil {
		s.failErr(w, err)
		return
	}
	s.write(w, 200, map[string]any{"runs": runs}, "")
}

func (s *Server) getRun(w http.ResponseWriter, r *http.Request) {
	d, err := s.Index.GetRun(s.runID(r))
	if err != nil {
		s.failErr(w, err)
		return
	}
	s.write(w, 200, d, s.runID(r))
}

func (s *Server) getAssets(w http.ResponseWriter, r *http.Request) {
	p, err := s.Index.Assets(s.runID(r), r.URL.Query().Get("filter"), intQ(r, "limit"), intQ(r, "offset"))
	if err != nil {
		s.failErr(w, err)
		return
	}
	s.write(w, 200, p, s.runID(r))
}

func (s *Server) getFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p, err := s.Index.Findings(s.runID(r), runindex.FindingFilter{
		Severity: q.Get("severity"), Asset: q.Get("asset"), Source: q.Get("source"), Kind: q.Get("kind"),
		Limit: intQ(r, "limit"), Offset: intQ(r, "offset"),
	})
	if err != nil {
		s.failErr(w, err)
		return
	}
	s.write(w, 200, p, s.runID(r))
}

func (s *Server) getEvidence(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	off, _ := strconv.ParseInt(q.Get("offset"), 10, 64)
	e, err := s.Index.Evidence(s.runID(r), q.Get("finding_id"), q.Get("file"), off, intQ(r, "max_bytes"))
	if err != nil {
		s.failErr(w, err)
		return
	}
	s.write(w, 200, e, s.runID(r))
}

func (s *Server) body(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		s.fail(w, 400, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func (s *Server) plan(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Target  string `json:"target"`
		Profile string `json:"profile"`
		WP      bool   `json:"wp"`
	}
	if !s.body(w, r, &b) {
		return
	}
	p, err := s.Active.Plan(active.PlanRequest{Target: b.Target, Profile: b.Profile, WP: b.WP})
	if err != nil {
		s.failErr(w, err)
		return
	}
	s.write(w, 200, p, "")
}

func (s *Server) startScan(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Target  string `json:"target"`
		Profile string `json:"profile"`
		DryRun  bool   `json:"dry_run"`
	}
	if !s.body(w, r, &b) {
		return
	}
	info, err := s.Active.Start(active.StartRequest{Target: b.Target, Profile: b.Profile, DryRun: b.DryRun})
	if err != nil {
		s.failErr(w, err)
		return
	}
	s.write(w, 202, info, "")
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	s.write(w, 200, map[string]any{"scans": s.Active.Scans(), "active_mode": s.Active.Allowed()}, "")
}

func (s *Server) stopScan(w http.ResponseWriter, r *http.Request) {
	info, err := s.Active.Stop(r.PathValue("id"))
	if err != nil {
		s.failErr(w, err)
		return
	}
	s.write(w, 200, info, "")
}
