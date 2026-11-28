// Package naabu wraps the naabu fast port scanner.
package naabu

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

type Module struct {
	binary string
}

func New(binary string) *Module {
	if binary == "" {
		binary = "naabu"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string        { return "naabu" }
func (m *Module) Description() string { return "Fast port scanner" }
func (m *Module) Requires() []string  { return []string{"resolved_hosts"} }
func (m *Module) Produces() []string  { return []string{"open_ports"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	inputArt, err := runCtx.MustArtifact("resolved_hosts")
	if err != nil {
		return nil, err
	}
	inputFile := runCtx.Run.Path(inputArt.Path)

	outputFile := runCtx.Run.Path("03_ports", "naabu.txt")
	stderrFile := runCtx.Run.Path("00_meta", "naabu.stderr.log")

	cmd := runner.Command{
		Name:       m.binary,
		Args:       []string{"-l", inputFile, "-silent"},
		Timeout:    30 * time.Minute,
		StdoutFile: outputFile,
		StderrFile: stderrFile,
	}

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, cmd); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	res, err := executor.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run command %q: %w", cmd.Name, err)
	}

	// Uncover is an optional, independent source of host:port pairs (internet-
	// wide search engines rather than an active probe). When selected, fold its
	// already scope-filtered results into naabu's own output before publishing,
	// exactly like dnsx merges optional subdomain producers - naabu's own
	// exit code/status stays authoritative; uncover's absence or failure never
	// fails this module. Skipped entirely in a dry run: there is nothing to
	// wait for since no module actually ran.
	if !runCtx.DryRun {
		art, found, werr := runCtx.WaitArtifact(ctx, "uncover_hosts")
		if werr != nil {
			return nil, fmt.Errorf("wait for optional uncover results: %w", werr)
		}
		if found {
			if err := mergeUniqueLines(outputFile, runCtx.Run.Path(art.Path)); err != nil {
				return nil, fmt.Errorf("failed to merge uncover results into open ports: %w", err)
			}
		}
	}

	if err := runCtx.AddArtifact("open_ports", modules.Artifact{
		Name:   "open_ports",
		Type:   "text",
		Path:   "03_ports/naabu.txt",
		Scoped: true,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish open ports: %w", err)
	}

	status := "completed"
	if res.ExitCode != 0 {
		status = modules.FailureStatus(res.ExitCode, stderrFile)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: status,
		OutputFiles: map[string]string{
			"open_ports":   "03_ports/naabu.txt",
			"naabu_stderr": "00_meta/naabu.stderr.log",
		},
	}, nil
}

// mergeUniqueLines appends every non-empty, non-duplicate line of srcPath to
// dstPath, which already exists (naabu's own raw output). A missing srcPath
// (the optional producer never published anything) is not an error.
func mergeUniqueLines(dstPath, srcPath string) error {
	existing := make(map[string]struct{})
	if f, err := os.Open(dstPath); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if line := strings.TrimSpace(scanner.Text()); line != "" {
				existing[line] = struct{}{}
			}
		}
		closeErr := f.Close()
		if scanErr := scanner.Err(); scanErr != nil {
			return scanErr
		}
		if closeErr != nil {
			return closeErr
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	src, err := os.Open(srcPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer func() { _ = src.Close() }()

	out, err := os.OpenFile(dstPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	writer := bufio.NewWriter(out)
	scanner := bufio.NewScanner(src)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if _, ok := existing[line]; ok {
			continue
		}
		existing[line] = struct{}{}
		if _, err := fmt.Fprintln(writer, line); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return writer.Flush()
}
