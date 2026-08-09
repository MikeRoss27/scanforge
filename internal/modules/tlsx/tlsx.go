// Package tlsx wraps the tlsx TLS/certificate enrichment tool.
package tlsx

import (
	"context"
	"fmt"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

type Module struct {
	binary string
}

func New(binary string) *Module {
	if binary == "" {
		binary = "tlsx"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string        { return "tlsx" }
func (m *Module) Description() string { return "TLS certificate and protocol enrichment" }
func (m *Module) Requires() []string  { return []string{"alive_urls"} }
func (m *Module) Produces() []string  { return []string{"tls_raw"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	input, err := runCtx.MustArtifact("alive_urls")
	if err != nil {
		return nil, err
	}
	outputFile := runCtx.Run.Path("02_http", "tlsx.jsonl")
	stderrFile := runCtx.Run.Path("00_meta", "tlsx.stderr.log")
	cmd := runner.Command{
		Name: m.binary,
		Args: []string{
			"-l", runCtx.Run.Path(input.Path),
			"-silent",
			"-json",
		},
		Timeout:    20 * time.Minute,
		StdoutFile: outputFile,
		StderrFile: stderrFile,
	}

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, cmd); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}
	if res, err := executor.Run(ctx, cmd); err != nil {
		return nil, fmt.Errorf("failed to run command %q: %w", cmd.Name, err)
	} else if err := runCtx.AddArtifact("tls_raw", modules.Artifact{
		Name: "tls_raw",
		Type: "jsonl",
		Path: "02_http/tlsx.jsonl",
	}); err != nil {
		return nil, fmt.Errorf("failed to publish TLS results: %w", err)
	} else {
		status := "completed"
		if res.ExitCode != 0 {
			status = fmt.Sprintf("failed (exit code %d)", res.ExitCode)
		}
		return &modules.Result{
			Name:   m.Name(),
			Status: status,
			OutputFiles: map[string]string{
				"tls_raw":     "02_http/tlsx.jsonl",
				"tlsx_stderr": "00_meta/tlsx.stderr.log",
			},
		}, nil
	}
}
