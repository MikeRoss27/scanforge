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
	return "Fast and multi-purpose HTTP toolkit"
}

func (m *Module) Requires() []string {
	return []string{"subdomains"} // We will fall back gracefully in Run
}

func (m *Module) Produces() []string {
	return []string{"httpx_raw", "alive_urls"}
}

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	// Try resolved_hosts first, fallback to subdomains
	inputArt, ok := runCtx.GetArtifact("resolved_hosts")
	if !ok {
		var err error
		inputArt, err = runCtx.MustArtifact("subdomains")
		if err != nil {
			return nil, err
		}
	}
	inputFile := runCtx.Run.Path(inputArt.Path)

	rawOutputFile := runCtx.Run.Path("02_http", "httpx.jsonl")
	aliveOutputFile := runCtx.Run.Path("02_http", "alive.txt")
	stderrFile := runCtx.Run.Path("00_meta", "httpx.stderr.log")

	cmd := runner.Command{
		Name: m.binary,
		Args: []string{
			"-l", inputFile,
			"-silent",
			"-json",
			"-status-code",
			"-title",
			"-tech-detect",
		},
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

	runCtx.AddArtifact("httpx_raw", modules.Artifact{
		Name: "httpx_raw",
		Type: "jsonl",
		Path: "02_http/httpx.jsonl",
	})
	runCtx.AddArtifact("alive_urls", modules.Artifact{
		Name: "alive_urls",
		Type: "text",
		Path: "02_http/alive.txt",
	})

	status := "completed"
	if res.ExitCode != 0 {
		status = fmt.Sprintf("failed (exit code %d)", res.ExitCode)
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
