// Package dnsx wraps the dnsx DNS resolution tool.
package dnsx

import (
	"bufio"
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
		binary = "dnsx"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string        { return "dnsx" }
func (m *Module) Description() string { return "Fast multi-purpose DNS toolkit" }
func (m *Module) Requires() []string  { return []string{"subdomains"} }
func (m *Module) Produces() []string  { return []string{"dnsx_raw", "resolved_hosts"} }

func (m *Module) SoftRequires() []string { return []string{"brute_subdomains"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	inputArt, err := runCtx.MustArtifact("subdomains")
	if err != nil {
		return nil, err
	}
	inputFile := mergeBruteInput(runCtx, inputArt)

	rawOutputFile := runCtx.Run.Path("01_subdomains", "dnsx.jsonl")
	resolvedOutputFile := runCtx.Run.Path("01_subdomains", "dnsx.txt")
	stderrFile := runCtx.Run.Path("00_meta", "dnsx.stderr.log")

	cmd := runner.Command{
		Name:       m.binary,
		Args:       []string{"-l", inputFile, "-silent", "-json", "-a", "-aaaa", "-cname", "-resp", "-cdn", "-asn"},
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
		if err := writeResolvedHosts(rawOutputFile, resolvedOutputFile); err != nil {
			return nil, fmt.Errorf("failed to derive resolved hosts: %w", err)
		}
	}
	if err := runCtx.AddArtifact("dnsx_raw", modules.Artifact{
		Name: "dnsx_raw",
		Type: "jsonl",
		Path: "01_subdomains/dnsx.jsonl",
	}); err != nil {
		return nil, fmt.Errorf("failed to publish DNS results: %w", err)
	}
	if err := runCtx.AddArtifact("resolved_hosts", modules.Artifact{
		Name: "resolved_hosts",
		Type: "text",
		Path: "01_subdomains/dnsx.txt",
	}); err != nil {
		return nil, fmt.Errorf("failed to publish resolved hosts: %w", err)
	}

	status := "completed"
	if res.ExitCode != 0 {
		status = fmt.Sprintf("failed (exit code %d)", res.ExitCode)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: status,
		OutputFiles: map[string]string{
			"dnsx_raw":       "01_subdomains/dnsx.jsonl",
			"resolved_hosts": "01_subdomains/dnsx.txt",
			"dnsx_stderr":    "00_meta/dnsx.stderr.log",
		},
	}, nil
}

// mergeBruteInput concatenates subfinder results and shuffledns bruteforce
// results into a single input file when the dnsbrute module ran. When there
// is nothing to merge it returns the subdomains artifact path unchanged.
func mergeBruteInput(runCtx *modules.RunContext, subdomains modules.Artifact) string {
	brute, ok := runCtx.GetArtifact("brute_subdomains")
	if !ok {
		return runCtx.Run.Path(subdomains.Path)
	}

	subdomainsFile := runCtx.Run.Path(subdomains.Path)
	bruteFile := runCtx.Run.Path(brute.Path)
	merged := runCtx.Run.Path("01_subdomains", "subdomains_all.txt")

	seen := make(map[string]struct{})
	var output []string
	for _, file := range []string{subdomainsFile, bruteFile} {
		input, err := os.Open(file)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(input)
		for scanner.Scan() {
			host := strings.TrimSpace(scanner.Text())
			if host == "" {
				continue
			}
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			output = append(output, host)
		}
		_ = input.Close()
	}

	if len(output) == 0 {
		return runCtx.Run.Path(subdomains.Path)
	}
	if err := os.WriteFile(merged, []byte(strings.Join(output, "\n")+"\n"), 0644); err != nil {
		return runCtx.Run.Path(subdomains.Path)
	}
	return merged
}

func writeResolvedHosts(inputPath, outputPath string) error {
	input, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()

	output, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer func() { _ = output.Close() }()

	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(input)
	writer := bufio.NewWriter(output)
	for scanner.Scan() {
		var record struct {
			Host string `json:"host"`
		}
		if json.Unmarshal(scanner.Bytes(), &record) != nil || record.Host == "" {
			continue
		}
		if _, ok := seen[record.Host]; ok {
			continue
		}
		seen[record.Host] = struct{}{}
		if _, err := fmt.Fprintln(writer, record.Host); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return writer.Flush()
}
