// Package httpx wraps the httpx HTTP probing and technology detection tool.
package httpx

import (
	"context"
	"encoding/json"
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
		binary = "httpx"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string {
	return "httpx"
}

func (m *Module) Description() string {
	return "Fast and multi-purpose HTTP toolkit (also probes open non-standard ports when naabu ran)"
}

func (m *Module) Requires() []string {
	return []string{"resolved_hosts"}
}

// SoftRequires makes httpx wait for naabu, when naabu is part of the profile,
// so web services on non-standard ports (8080, 8443, 3000...) are probed too.
// Without naabu in the profile httpx runs as soon as resolved_hosts exists.
func (m *Module) SoftRequires() []string {
	return []string{"open_ports"}
}

func (m *Module) Produces() []string {
	return []string{"httpx_raw", "alive_urls"}
}

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	inputArt, err := runCtx.MustArtifact("resolved_hosts")
	if err != nil {
		return nil, err
	}
	inputFile := runCtx.Run.Path(inputArt.Path)

	// Merge the scope-filtered naabu results (host:port) into the probe list.
	// open_ports was already filtered by the artifact scope choke point.
	if portsArt, ok := runCtx.GetArtifact("open_ports"); ok && !runCtx.DryRun {
		merged := runCtx.Run.Path("02_http", "httpx-input.txt")
		n, err := writeProbeTargets(inputFile, runCtx.Run.Path(portsArt.Path), merged)
		if err != nil {
			return nil, fmt.Errorf("failed to build httpx input: %w", err)
		}
		if n > 0 {
			inputFile = merged
		}
	}

	// A port the user wrote in their own target (http://host:8082) is an
	// intentional probe: subfinder/dnsx only carry hosts, so without this the
	// port would be lost and only 80/443 probed.
	if !runCtx.DryRun {
		if hint, ok := targetHintProbe(runCtx, runCtx.Run.Path(inputArt.Path)); ok {
			merged := runCtx.Run.Path("02_http", "httpx-input.txt")
			if err := appendProbeTarget(inputFile, merged, hint); err != nil {
				return nil, fmt.Errorf("failed to add target port to httpx input: %w", err)
			}
			inputFile = merged
		}
	}

	rawOutputFile := runCtx.Run.Path("02_http", "httpx.jsonl")
	aliveOutputFile := runCtx.Run.Path("02_http", "alive.txt")
	stderrFile := runCtx.Run.Path("00_meta", "httpx.stderr.log")

	args := []string{
		"-l", inputFile,
		"-silent",
		"-json",
		"-status-code",
		"-title",
		"-tech-detect",
		"-server",
		"-ip",
		"-cname",
		"-cdn",
		"-location",
		"-content-type",
		"-content-length",
		"-favicon",
		"-response-time",
	}
	args = append(args, runCtx.ProxyArgs("-proxy")...)
	args = append(args, runCtx.HeaderArgs("-H")...)

	cmd := runner.Command{
		Name:       m.binary,
		Args:       args,
		Timeout:    10 * time.Minute,
		StdoutFile: rawOutputFile,
		StderrFile: stderrFile,
	}

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, cmd); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	res, err := executor.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run command %q: %w", cmd.Name, err)
	}

	if !runCtx.DryRun {
		if _, err := os.Stat(rawOutputFile); err == nil {
			if err := writeAliveURLs(rawOutputFile, aliveOutputFile); err != nil {
				return nil, fmt.Errorf("failed to write alive URLs: %w", err)
			}
		}
	}

	if err := runCtx.AddArtifact("httpx_raw", modules.Artifact{
		Name: "httpx_raw",
		Type: "jsonl",
		Path: "02_http/httpx.jsonl",
	}); err != nil {
		return nil, fmt.Errorf("failed to publish HTTP results: %w", err)
	}
	if err := runCtx.AddArtifact("alive_urls", modules.Artifact{
		Name:   "alive_urls",
		Type:   "text",
		Path:   "02_http/alive.txt",
		Scoped: true,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish alive URLs: %w", err)
	}

	status := "completed"
	if res.ExitCode != 0 {
		status = modules.FailureStatus(res.ExitCode, stderrFile)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: status,
		OutputFiles: map[string]string{
			"httpx_raw":    "02_http/httpx.jsonl",
			"alive_urls":   "02_http/alive.txt",
			"httpx_stderr": "00_meta/httpx.stderr.log",
		},
	}, nil
}

func writeAliveURLs(inputPath, outputPath string) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	var urls []string
	seen := make(map[string]bool)

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var record struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal([]byte(line), &record); err == nil && record.URL != "" {
			if !seen[record.URL] {
				seen[record.URL] = true
				urls = append(urls, record.URL)
			}
		}
	}

	return os.WriteFile(outputPath, []byte(strings.Join(urls, "\n")+"\n"), 0644)
}
