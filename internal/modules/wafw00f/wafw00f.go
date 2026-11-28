// Package wafw00f wraps the wafw00f WAF detection tool.
package wafw00f

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

// wafNamePattern matches wafw00f's "is behind <product> WAF" verdict line
// and captures the product name, e.g. "The site ... is behind Cloudflare
// (Cloudflare Inc.) WAF." -> "Cloudflare (Cloudflare Inc.)".
var wafNamePattern = regexp.MustCompile(`(?i)is behind (?:a |an )?(.+?)(?: WAF)?(?:\.|$)`)

type Module struct {
	binary string
}

func New(binary string) *Module {
	if binary == "" {
		binary = "wafw00f"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string        { return "wafw00f" }
func (m *Module) Description() string { return "Web application firewall fingerprinting tool" }
func (m *Module) Requires() []string  { return []string{"alive_urls"} }
func (m *Module) Produces() []string  { return []string{"waf_raw"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	inputArt, err := runCtx.MustArtifact("alive_urls")
	if err != nil {
		return nil, err
	}
	inputFile := runCtx.Run.Path(inputArt.Path)

	outputFile := runCtx.Run.Path("04_web", "wafw00f.txt")
	stderrFile := runCtx.Run.Path("00_meta", "wafw00f.stderr.log")

	cmd := runner.Command{
		Name:       m.binary,
		Args:       []string{"-i", inputFile},
		Timeout:    20 * time.Minute,
		StdoutFile: outputFile,
		StderrFile: stderrFile,
	}
	cmd.Args = append(cmd.Args, runCtx.ProxyArgs("-p")...)

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, cmd); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	res, err := executor.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run command %q: %w", cmd.Name, err)
	}

	if err := runCtx.AddArtifact("waf_raw", modules.Artifact{
		Name: "waf_raw",
		Type: "text",
		Path: "04_web/wafw00f.txt",
	}); err != nil {
		return nil, fmt.Errorf("failed to publish WAF results: %w", err)
	}

	if names := detectWAFNames(outputFile); len(names) > 0 {
		runCtx.SetWAFInfo(modules.WAFInfo{Detected: true, Names: names})
	}

	status := "completed"
	if res.ExitCode != 0 {
		status = modules.FailureStatus(res.ExitCode, stderrFile)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: status,
		OutputFiles: map[string]string{
			"waf_raw":        "04_web/wafw00f.txt",
			"wafw00f_stderr": "00_meta/wafw00f.stderr.log",
		},
	}, nil
}

// detectWAFNames scans wafw00f's text output for its "is behind ... WAF"
// verdict and returns the distinct product names found, or nil when no WAF
// was reported (missing file counts as "no WAF").
func detectWAFNames(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var names []string
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		match := wafNamePattern.FindStringSubmatch(scanner.Text())
		if len(match) != 2 {
			continue
		}
		name := strings.TrimSpace(match[1])
		if name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names
}
