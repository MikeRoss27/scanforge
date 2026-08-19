// Package subfinder wraps the subfinder subdomain discovery tool.
package subfinder

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/url"
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
		binary = "subfinder"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string {
	return "subfinder"
}

func (m *Module) Description() string {
	return "Fast passive subdomain enumeration tool"
}

func (m *Module) Requires() []string {
	return nil // No required artifacts, uses Target
}

func (m *Module) Produces() []string {
	return []string{"subdomains"}
}

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	outputFile := runCtx.Run.Path("01_subdomains", "subfinder.txt")
	stderrFile := runCtx.Run.Path("00_meta", "subfinder.stderr.log")
	target, err := enumerationTarget(runCtx.Target)
	if err != nil {
		return nil, err
	}

	cmd := runner.Command{
		Name:       m.binary,
		Args:       []string{"-d", target, "-silent"},
		Timeout:    10 * time.Minute,
		StdoutFile: outputFile,
		StderrFile: stderrFile,
	}
	cmd.Args = append(cmd.Args, runCtx.ProxyArgs("-proxy")...)

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, cmd); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	res, err := executor.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run command %q: %w", cmd.Name, err)
	}

	if !runCtx.DryRun {
		if err := ensureTargetInOutput(outputFile, target); err != nil {
			return nil, fmt.Errorf("include root target in subfinder output: %w", err)
		}
	}

	if err := runCtx.AddArtifact("subdomains", modules.Artifact{
		Name:   "subdomains",
		Type:   "text",
		Path:   "01_subdomains/subfinder.txt",
		Scoped: true,
	}); err != nil {
		return nil, fmt.Errorf("publish subdomains artifact: %w", err)
	}

	status := "completed"
	if res.ExitCode != 0 {
		status = fmt.Sprintf("failed (exit code %d)", res.ExitCode)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: status,
		OutputFiles: map[string]string{
			"subfinder":        "01_subdomains/subfinder.txt",
			"subfinder_stderr": "00_meta/subfinder.stderr.log",
		},
	}, nil
}

func enumerationTarget(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("subfinder target is empty")
	}

	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Hostname() == "" {
			return "", fmt.Errorf("invalid subfinder target %q", raw)
		}
		value = parsed.Hostname()
	} else if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}

	value = strings.Trim(strings.TrimSuffix(value, "."), "[]")
	if value == "" || strings.ContainsAny(value, "/?#") {
		return "", fmt.Errorf("invalid subfinder target %q", raw)
	}
	return strings.ToLower(value), nil
}

func ensureTargetInOutput(path, target string) error {
	input, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()

	scanner := bufio.NewScanner(input)
	hasTarget := false
	hasContent := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			hasContent = true
		}
		if strings.EqualFold(line, target) {
			hasTarget = true
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if hasTarget {
		return nil
	}
	if _, err := input.Seek(0, 2); err != nil {
		return err
	}
	prefix := ""
	if hasContent {
		prefix = "\n"
	}
	_, err = input.WriteString(prefix + target + "\n")
	return err
}
