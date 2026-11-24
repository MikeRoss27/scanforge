// Package dnsx wraps the dnsx DNS resolution tool.
package dnsx

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
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

	// dnsx resolves hostnames; fed an address that is already an IP
	// literal (the common case when the scan target itself is a bare IP),
	// it has nothing to look up and silently produces no output line for
	// it - no error, no warning, just a missing entry. That emptied the
	// whole pipeline downstream (naabu/httpx get an empty resolved_hosts)
	// while the run still reported "completed". IP literals are split out
	// here and published directly below instead of being sent through the
	// subprocess; only genuine hostnames go through dnsx.
	//
	// This inspection needs the subdomains artifact to actually exist on
	// disk, which a dry run never writes (the executor never runs
	// subfinder for real): skip it entirely in that case and fall back to
	// the original, unconditional dnsx invocation below, exactly as
	// before this change - a dry run only ever records intended commands.
	var ips, hostnames []string
	passiveInputFile := inputFile
	skipPassiveDNSX := false
	if !runCtx.DryRun {
		var splitErr error
		ips, hostnames, splitErr = splitIPLiterals(inputFile)
		if splitErr != nil {
			return nil, fmt.Errorf("failed to inspect subdomains for IP literals: %w", splitErr)
		}
		skipPassiveDNSX = len(ips) > 0 && len(hostnames) == 0
		if len(ips) > 0 && len(hostnames) > 0 {
			passiveInputFile = runCtx.Run.Path("01_subdomains", "dnsx-input-hosts.txt")
			if err := os.WriteFile(passiveInputFile, []byte(strings.Join(hostnames, "\n")+"\n"), 0644); err != nil {
				return nil, fmt.Errorf("failed to write filtered DNS input: %w", err)
			}
		}
	}

	var passiveResult *runner.CommandResult
	if skipPassiveDNSX {
		// Every input line is already an IP literal: nothing for dnsx to
		// resolve. Record the skip for the audit trail and seed an empty
		// raw file so the merge step below has something to open.
		skipCmd := runner.Command{Name: "dnsx (skipped)", Args: []string{"-ip-literals", strings.Join(ips, ",")}}
		if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, skipCmd); err != nil {
			return nil, fmt.Errorf("failed to write commands log: %w", err)
		}
		if err := os.WriteFile(passiveRawFile, nil, 0644); err != nil {
			return nil, fmt.Errorf("failed to initialize DNS results: %w", err)
		}
		passiveResult = &runner.CommandResult{}
	} else {
		passiveResult, err = m.runDNSX(ctx, runCtx, executor, passiveInputFile, passiveRawFile, stderrFile)
		if err != nil {
			return nil, err
		}
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
	// Certificate Transparency names (ctlogs) feed the same flow: they are
	// scope-filtered at publication and resolved here like brute-force hits,
	// without a second producer of "subdomains".
	for _, optional := range []struct{ artifact, label, file string }{
		{"brute_subdomains", "brute-force", "brute"},
		{"ct_subdomains", "certificate transparency", "ct"},
	} {
		art, found, werr := runCtx.WaitArtifact(ctx, optional.artifact)
		if werr != nil {
			return nil, fmt.Errorf("wait for optional %s DNS results: %w", optional.label, werr)
		}
		if !found {
			continue
		}
		if info, statErr := os.Stat(runCtx.Run.Path(art.Path)); !runCtx.DryRun && optional.artifact == "ct_subdomains" && (statErr != nil || info.Size() == 0) {
			continue // nothing left after discovery/scope filtering
		}
		rawFile := runCtx.Run.Path("01_subdomains", "dnsx-"+optional.file+".jsonl")
		stderrName := "dnsx-" + optional.file + ".stderr.log"
		optResult, runErr := m.runDNSX(ctx, runCtx, executor, runCtx.Run.Path(art.Path), rawFile, runCtx.Run.Path("00_meta", stderrName))
		if runErr != nil {
			return nil, fmt.Errorf("resolve %s DNS results: %w", optional.label, runErr)
		}
		rawInputs = append(rawInputs, rawFile)
		exitCodes = append(exitCodes, optResult.ExitCode)
		outputFiles["dnsx_"+optional.file+"_stderr"] = "00_meta/" + stderrName
	}

	if !runCtx.DryRun {
		if err := mergeLineFiles(rawOutputFile, rawInputs...); err != nil {
			return nil, fmt.Errorf("failed to merge DNS results: %w", err)
		}
		if len(ips) > 0 {
			if err := appendIPLiteralRecords(rawOutputFile, ips); err != nil {
				return nil, fmt.Errorf("failed to publish IP literal targets: %w", err)
			}
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

// splitIPLiterals separates a subdomains-artifact file's lines into IP
// literals (which dnsx cannot meaningfully "resolve") and genuine hostnames.
func splitIPLiterals(path string) (ips []string, hostnames []string, err error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if net.ParseIP(line) != nil {
			ips = append(ips, line)
		} else {
			hostnames = append(hostnames, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return ips, hostnames, nil
}

// appendIPLiteralRecords appends one dnsx-shaped JSON line per IP literal to
// path, so a bare-IP target flows into resolved_hosts exactly like a
// genuinely resolved hostname would, instead of disappearing silently.
func appendIPLiteralRecords(path string, ips []string) error {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	writer := bufio.NewWriter(file)
	for _, ip := range ips {
		record := struct {
			Host string   `json:"host"`
			A    []string `json:"a,omitempty"`
			AAAA []string `json:"aaaa,omitempty"`
		}{Host: ip}
		if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil {
			record.A = []string{ip}
		} else {
			record.AAAA = []string{ip}
		}
		data, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if _, err := writer.Write(data); err != nil {
			return err
		}
		if err := writer.WriteByte('\n'); err != nil {
			return err
		}
	}
	return writer.Flush()
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
