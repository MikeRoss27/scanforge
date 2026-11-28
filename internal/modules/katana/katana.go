// Package katana wraps the katana web crawler.
package katana

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

type Module struct {
	binary string
}

func New(binary string) *Module {
	if binary == "" {
		binary = "katana"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string        { return "katana" }
func (m *Module) Description() string { return "A next-generation crawling and spidering framework" }
func (m *Module) Requires() []string  { return []string{"alive_urls"} }
func (m *Module) Produces() []string  { return []string{"crawled_urls"} }

// SoftRequires waits for wafw00f to finish, when it's part of the profile,
// so WAF detection (GetWAFInfo) is settled before the crawl starts.
func (m *Module) SoftRequires() []string { return []string{"waf_raw"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	inputArt, focus, err := runCtx.FocusedInput("alive_urls")
	if err != nil {
		return nil, err
	}
	inputFile := runCtx.Run.Path(inputArt.Path)

	outputFile := runCtx.Run.Path("05_content", "katana.txt")
	stderrFile := runCtx.Run.Path("00_meta", "katana.stderr.log")

	if focus.Empty() {
		// Incremental run with nothing new or changed: publish an empty
		// crawl so downstream modules still resolve their input.
		if err := os.WriteFile(outputFile, nil, 0o644); err != nil {
			return nil, fmt.Errorf("failed to write empty crawl: %w", err)
		}
		if err := runCtx.AddArtifact("crawled_urls", modules.Artifact{
			Name: "crawled_urls", Type: "text", Path: "05_content/katana.txt", Scoped: true,
		}); err != nil {
			return nil, fmt.Errorf("failed to publish crawled URLs: %w", err)
		}
		return &modules.Result{
			Name: m.Name(), Status: "skipped", Reason: focus.SkipReason(),
			OutputFiles: map[string]string{"crawled_urls": "05_content/katana.txt"},
		}, nil
	}

	// -jc parses JavaScript files for endpoints, so the crawl reaches
	// bundles/chunks referenced from scripts instead of only HTML links.
	args := []string{"-list", inputFile, "-silent", "-depth", "2", "-jc"}
	if waf := runCtx.GetWAFInfo(); waf.Detected {
		// Throttle the crawl (requests/sec) and lower concurrency instead of
		// katana's defaults, so the crawl doesn't look like a burst of
		// scripted requests to the filtering edge wafw00f just found.
		args = append(args, "-rate-limit", "5", "-c", "2")
		if !modules.HasHeaderNamed(runCtx.Headers, "User-Agent") {
			args = append(args, "-H", "User-Agent: "+modules.RandomUserAgent())
		}
	}
	args = append(args, runCtx.ProxyArgs("-proxy")...)
	args = append(args, runCtx.HeaderArgs("-H")...)

	cmd := runner.Command{
		Name:       m.binary,
		Args:       args,
		Timeout:    45 * time.Minute,
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

	if err := runCtx.AddArtifact("crawled_urls", modules.Artifact{
		Name:   "crawled_urls",
		Type:   "text",
		Path:   "05_content/katana.txt",
		Scoped: true,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish crawled URLs: %w", err)
	}

	status := "completed"
	if res.ExitCode != 0 {
		status = modules.FailureStatus(res.ExitCode, stderrFile)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: status,
		OutputFiles: map[string]string{
			"crawled_urls":  "05_content/katana.txt",
			"katana_stderr": "00_meta/katana.stderr.log",
		},
	}, nil
}
