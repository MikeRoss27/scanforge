// Package mcp implements a minimal Model Context Protocol server over stdio
// (newline-delimited JSON-RPC 2.0: initialize, ping, tools/list, tools/call).
// Read tools are always available; start_authorized_scan and stop_scan are
// gated by the active.Controller.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/MikeRoss27/scanforge/internal/active"
	"github.com/MikeRoss27/scanforge/internal/runindex"
)

const defaultProtocol = "2025-06-18"

var supportedProtocols = map[string]bool{"2024-11-05": true, "2025-03-26": true, "2025-06-18": true}

// Server serves the tools.
type Server struct {
	Index   *runindex.Index
	Active  *active.Controller
	Version string
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// Serve reads requests from in until EOF or ctx cancellation.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	var mu sync.Mutex
	write := func(r response) {
		r.JSONRPC = "2.0"
		data, err := json.Marshal(r)
		if err != nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		_, _ = out.Write(append(data, '\n'))
	}
	reader := bufio.NewReaderSize(in, 1<<20)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line, err := reader.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			s.handleLine(bytes.TrimSpace(line), write)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func (s *Server) handleLine(line []byte, write func(response)) {
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		write(response{ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}})
		return
	}
	isNotification := len(req.ID) == 0
	result, rerr := s.dispatch(req)
	if isNotification {
		return
	}
	if rerr != nil {
		write(response{ID: req.ID, Error: rerr})
		return
	}
	write(response{ID: req.ID, Result: result})
}

func (s *Server) dispatch(req request) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		version := defaultProtocol
		if supportedProtocols[p.ProtocolVersion] {
			version = p.ProtocolVersion
		}
		return map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "scanforge", "version": s.Version},
			"instructions": "Read tools expose past runs from the local run store. " +
				"Active tools (start_authorized_scan, stop_scan) are disabled unless the operator started the server with --allow-active and an explicit --scope file.",
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": toolDefs()}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, &rpcError{-32602, "invalid params"}
		}
		if !knownTool(p.Name) {
			return nil, &rpcError{-32602, "unknown tool: " + p.Name}
		}
		return s.callTool(p.Name, p.Arguments), nil
	default:
		if strings.HasPrefix(req.Method, "notifications/") {
			return nil, nil
		}
		return nil, &rpcError{-32601, "method not found: " + req.Method}
	}
}

type toolResult struct {
	Content []map[string]string `json:"content"`
	IsError bool                `json:"isError,omitempty"`
}

func textResult(text string, isErr bool) toolResult {
	return toolResult{Content: []map[string]string{{"type": "text", "text": text}}, IsError: isErr}
}

func errResult(err error) toolResult { return textResult("error: "+err.Error(), true) }

// decode strictly parses arguments: unknown fields (for example a client
// trying to pass headers, cookies or keys) are rejected.
func decode(raw json.RawMessage, dst any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = json.RawMessage("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid arguments: %w", err)
	}
	return nil
}

func (s *Server) encode(v any, runID string) toolResult {
	data, err := s.Index.Encode(v, runID)
	if err != nil {
		return errResult(err)
	}
	return textResult(string(data), false)
}

func (s *Server) callTool(name string, raw json.RawMessage) toolResult {
	switch name {
	case "scanforge.list_runs":
		var a struct {
			Target string `json:"target"`
			Limit  int    `json:"limit"`
		}
		if err := decode(raw, &a); err != nil {
			return errResult(err)
		}
		runs, err := s.Index.ListRuns(a.Target, a.Limit)
		if err != nil {
			return errResult(err)
		}
		out := map[string]any{"runs": runs, "active_mode": s.Active.Allowed()}
		if s.Active.Allowed() {
			out["active_scans"] = s.Active.Scans()
		}
		return s.encode(out, "")
	case "scanforge.get_run":
		var a struct {
			RunID string `json:"run_id"`
		}
		if err := decode(raw, &a); err != nil {
			return errResult(err)
		}
		d, err := s.Index.GetRun(a.RunID)
		if err != nil {
			return errResult(err)
		}
		return s.encode(d, a.RunID)
	case "scanforge.get_assets":
		var a struct {
			RunID  string `json:"run_id"`
			Filter string `json:"filter"`
			Limit  int    `json:"limit"`
			Offset int    `json:"offset"`
		}
		if err := decode(raw, &a); err != nil {
			return errResult(err)
		}
		p, err := s.Index.Assets(a.RunID, a.Filter, a.Limit, a.Offset)
		if err != nil {
			return errResult(err)
		}
		return s.encode(p, a.RunID)
	case "scanforge.get_findings":
		var a struct {
			RunID    string `json:"run_id"`
			Severity string `json:"severity"`
			Asset    string `json:"asset"`
			Source   string `json:"source"`
			Kind     string `json:"kind"`
			Limit    int    `json:"limit"`
			Offset   int    `json:"offset"`
		}
		if err := decode(raw, &a); err != nil {
			return errResult(err)
		}
		p, err := s.Index.Findings(a.RunID, runindex.FindingFilter{Severity: a.Severity, Asset: a.Asset, Source: a.Source, Kind: a.Kind, Limit: a.Limit, Offset: a.Offset})
		if err != nil {
			return errResult(err)
		}
		return s.encode(p, a.RunID)
	case "scanforge.get_evidence":
		var a struct {
			RunID     string `json:"run_id"`
			FindingID string `json:"finding_id"`
			File      string `json:"file"`
			Offset    int64  `json:"offset"`
			MaxBytes  int    `json:"max_bytes"`
		}
		if err := decode(raw, &a); err != nil {
			return errResult(err)
		}
		e, err := s.Index.Evidence(a.RunID, a.FindingID, a.File, a.Offset, a.MaxBytes)
		if err != nil {
			return errResult(err)
		}
		return s.encode(e, a.RunID)
	case "scanforge.plan_scan":
		var a struct {
			Target  string `json:"target"`
			Profile string `json:"profile"`
			WP      bool   `json:"wp"`
		}
		if err := decode(raw, &a); err != nil {
			return errResult(err)
		}
		p, err := s.Active.Plan(active.PlanRequest{Target: a.Target, Profile: a.Profile, WP: a.WP})
		if err != nil {
			return errResult(err)
		}
		return s.encode(p, "")
	case "scanforge.start_authorized_scan":
		var a struct {
			Target  string `json:"target"`
			Profile string `json:"profile"`
			DryRun  bool   `json:"dry_run"`
		}
		if err := decode(raw, &a); err != nil {
			return errResult(err)
		}
		info, err := s.Active.Start(active.StartRequest{Target: a.Target, Profile: a.Profile, DryRun: a.DryRun})
		if err != nil {
			return errResult(err)
		}
		return s.encode(info, "")
	case "scanforge.stop_scan":
		var a struct {
			ScanID string `json:"scan_id"`
		}
		if err := decode(raw, &a); err != nil {
			return errResult(err)
		}
		info, err := s.Active.Stop(a.ScanID)
		if err != nil {
			return errResult(err)
		}
		return s.encode(info, "")
	}
	return errResult(fmt.Errorf("unknown tool %q", name))
}
