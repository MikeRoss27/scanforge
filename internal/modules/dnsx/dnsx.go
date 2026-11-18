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

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	inputArt, err := runCtx.MustArtifact("subdomains")
	if err != nil {
		return nil, err
	}
	inputFile := runCtx.Run.Path(inputArt.Path)
	passiveRawFile := runCtx.Run.Path("01_subdomains", "dnsx-passive.jsonl")
	rawOutputFile := runCtx.Run.Path("01_subdomains", "dnsx.jsonl")
	resolvedOutputFile := runCtx.Run.Path("01_subdomains", "dnsx.txt")
	stderrFile := runCtx.Run.Path("00_meta", "dnsx.stderr.log")

	passiveResult, err := m.runDNSX(ctx, runCtx, executor, inputFile, passiveRawFile, stderrFile)
	if err != nil {
		return nil, err
	}

	rawInputs := []string{passiveRawFile}
	outputFiles := map[string]string{
		"dnsx_raw":       "01_subdomains/dnsx.jsonl",
		"resolved_hosts": "01_subdomains/dnsx.txt",
		"dnsx_stderr":    "00_meta/dnsx.stderr.log",
	}
	exitCodes := []int{passiveResult.ExitCode}

	// DNS bruteforce is optional, but when selected its producer lifecycle is
	// tracked by RunContext. Passive DNS resolution has already completed while
	// shuffledns was running; only the late brute-force results are resolved now.
	brute, hasBrute, err := runCtx.WaitArtifact(ctx, "brute_subdomains")
	if err != nil {
		return nil, fmt.Errorf("wait for optional brute-force DNS results: %w", err)
	}
	if hasBrute {
		bruteRawFile := runCtx.Run.Path("01_subdomains", "dnsx-brute.jsonl")
		bruteStderrFile := runCtx.Run.Path("00_meta", "dnsx-brute.stderr.log")
		bruteResult, runErr := m.runDNSX(ctx, runCtx, executor, runCtx.Run.Path(brute.Path), bruteRawFile, bruteStderrFile)
		if runErr != nil {
			return nil, fmt.Errorf("resolve brute-force DNS results: %w", runErr)
		}
		rawInputs = append(rawInputs, bruteRawFile)
		exitCodes = append(exitCodes, bruteResult.ExitCode)
		outputFiles["dnsx_brute_stderr"] = "00_meta/dnsx-brute.stderr.log"
	}

	if !runCtx.DryRun {
		if err := mergeLineFiles(rawOutputFile, rawInputs...); err != nil {
			return nil, fmt.Errorf("failed to merge DNS results: %w", err)
		}
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
		Name:   "resolved_hosts",
		Type:   "text",
		Path:   "01_subdomains/dnsx.txt",
		Scoped: true,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish resolved hosts: %w", err)
	}

	status := "completed"
	for _, exitCode := range exitCodes {
		if exitCode != 0 {
			status = fmt.Sprintf("failed (exit code %d)", exitCode)
			break
		}
	}

	return &modules.Result{
		Name:        m.Name(),
		Status:      status,
		OutputFiles: outputFiles,
	}, nil
}

func (m *Module) runDNSX(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor, inputFile, outputFile, stderrFile string) (*runner.CommandResult, error) {
	cmd := runner.Command{
		Name:       m.binary,
		Args:       []string{"-l", inputFile, "-silent", "-json", "-a", "-aaaa", "-cname", "-resp", "-cdn", "-asn"},
		Timeout:    10 * time.Minute,
		StdoutFile: outputFile,
		StderrFile: stderrFile,
	}
	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, cmd); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}
	result, err := executor.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run command %q: %w", cmd.Name, err)
	}
	return result, nil
}

func mergeLineFiles(outputPath string, inputPaths ...string) error {
	output, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer func() { _ = output.Close() }()

	writer := bufio.NewWriter(output)
	seen := make(map[string]struct{})
	for _, path := range inputPaths {
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		scanner := bufio.NewScanner(input)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			if _, ok := seen[line]; ok {
				continue
			}
			seen[line] = struct{}{}
			if _, err := fmt.Fprintln(writer, line); err != nil {
				_ = input.Close()
				return err
			}
		}
		scanErr := scanner.Err()
		closeErr := input.Close()
		if scanErr != nil {
			return scanErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return writer.Flush()
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
