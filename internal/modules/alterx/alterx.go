// Package alterx wraps ProjectDiscovery's own alterx permutation engine.
//
// It does the same job as the shuffledns/dnsbrute bruteforce chain -
// generating candidate subdomains from known ones - but with a different
// engine, deliberately kept side by side with dnsbrute: alterx's pattern
// library and built-in enrichment find different candidates than a
// wordlist-driven bruteforce does. Candidates are published as the
// "altered_subdomains" scoped text artifact, so the central scope filter
// (RunContext.AddArtifact) drops anything outside the effective scope before
// dnsx - which merges the artifact into the normal subdomain flow, exactly
// like brute_subdomains/ct_subdomains - resolves it.
package alterx

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

const (
	// maxAlterxSeedDomains caps how many discovered domains are fed to
	// alterx as permutation seeds, mirroring dnsbrute's bruteforce cap: each
	// seed multiplies alterx's internal pattern set, so a large subdomain
	// discovery cannot fan out into an unbounded permutation run.
	maxAlterxSeedDomains = 20
	// maxAlterxCandidates caps the number of permutations kept after
	// de-duplication and seed removal, so a pathological alterx run cannot
	// hand dnsx an unbounded resolution workload.
	maxAlterxCandidates = 5000
)

type Module struct {
	binary string
}

func New(binary string) *Module {
	if binary == "" {
		binary = "alterx"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string { return "alterx" }
func (m *Module) Description() string {
	return "Generates subdomain permutations with alterx (ProjectDiscovery's own permutation engine)"
}
func (m *Module) Requires() []string { return []string{"subdomains"} }
func (m *Module) Produces() []string { return []string{"altered_subdomains"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	inputArt, err := runCtx.MustArtifact("subdomains")
	if err != nil {
		return nil, err
	}
	inputFile := runCtx.Run.Path(inputArt.Path)

	seeds, err := readSeeds(inputFile)
	if err != nil {
		return nil, err
	}
	if len(seeds) == 0 && runCtx.DryRun && runCtx.Target != "" {
		// A dry run never executes subfinder, so the artifact has no
		// content: show the command against the scan target instead of
		// failing.
		seeds = []string{runCtx.Target}
	}
	if len(seeds) == 0 {
		return nil, fmt.Errorf("no domains to permute (subdomains artifact is empty)")
	}

	seedFile := runCtx.Run.Path("01_subdomains", "alterx-seeds.txt")
	if err := os.WriteFile(seedFile, []byte(strings.Join(seeds, "\n")+"\n"), 0644); err != nil {
		return nil, fmt.Errorf("failed to write alterx seed file: %w", err)
	}

	rawOutputFile := runCtx.Run.Path("01_subdomains", "alterx-raw.txt")
	outputFile := runCtx.Run.Path("01_subdomains", "alterx.txt")
	stderrFile := runCtx.Run.Path("00_meta", "alterx.stderr.log")

	// alterx has its own pattern library and enrichment data, so -enrich
	// alone gets permutations without pointing it at a bundled wordlist the
	// way gotator/dnsbrute need one. Output goes through -o rather than
	// stdout, matching alterx's own CLI convention.
	cmd := runner.Command{
		Name:       m.binary,
		Args:       []string{"-l", seedFile, "-o", rawOutputFile, "-enrich", "-silent"},
		Timeout:    5 * time.Minute,
		StderrFile: stderrFile,
	}

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, cmd); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	res, err := executor.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run command %q: %w", cmd.Name, err)
	}

	if runCtx.DryRun {
		// The dry-run executor never touches rawOutputFile: publish an
		// empty candidate list instead of post-processing a file that was
		// never written.
		if err := os.WriteFile(outputFile, nil, 0644); err != nil {
			return nil, fmt.Errorf("failed to write alterx output: %w", err)
		}
	} else if err := writeCandidates(seeds, rawOutputFile, outputFile, maxAlterxCandidates); err != nil {
		return nil, fmt.Errorf("failed to post-process alterx output: %w", err)
	}

	if err := runCtx.AddArtifact("altered_subdomains", modules.Artifact{
		Name:   "altered_subdomains",
		Type:   "text",
		Path:   "01_subdomains/alterx.txt",
		Scoped: true,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish altered subdomains: %w", err)
	}

	status := "completed"
	if res.ExitCode != 0 {
		status = modules.FailureStatus(res.ExitCode, stderrFile)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: status,
		OutputFiles: map[string]string{
			"altered_subdomains": "01_subdomains/alterx.txt",
			"alterx_stderr":      "00_meta/alterx.stderr.log",
		},
	}, nil
}

// readSeeds returns the trimmed, de-duplicated, non-empty lines of the
// subdomains artifact. The list is capped so a large subdomain discovery can
// never fan out into an unbounded number of alterx permutation seeds.
func readSeeds(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read subdomains artifact: %w", err)
	}
	defer func() { _ = file.Close() }()

	seen := make(map[string]bool)
	var seeds []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		seed := strings.TrimSpace(scanner.Text())
		if seed == "" || seen[seed] {
			continue
		}
		seen[seed] = true
		seeds = append(seeds, seed)
		if len(seeds) >= maxAlterxSeedDomains {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read subdomains artifact: %w", err)
	}
	return seeds, nil
}

// writeCandidates de-duplicates alterx's raw permutation output, drops lines
// identical to one of the original seeds (alterx frequently echoes the seed
// itself as a "permutation"), caps the result at max, and writes it to
// outPath. A missing raw file (nothing produced) yields an empty output
// file rather than an error.
func writeCandidates(seeds []string, rawPath, outPath string, max int) error {
	seedSet := make(map[string]struct{}, len(seeds))
	for _, s := range seeds {
		seedSet[strings.ToLower(s)] = struct{}{}
	}

	input, err := os.Open(rawPath)
	if err != nil {
		if os.IsNotExist(err) {
			return os.WriteFile(outPath, nil, 0644)
		}
		return fmt.Errorf("failed to read alterx raw output: %w", err)
	}
	defer func() { _ = input.Close() }()

	output, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("failed to create alterx output: %w", err)
	}
	defer func() { _ = output.Close() }()

	seen := make(map[string]struct{})
	writer := bufio.NewWriter(output)
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	count := 0
	for scanner.Scan() && count < max {
		line := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if line == "" {
			continue
		}
		if _, ok := seedSet[line]; ok {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		if _, err := fmt.Fprintln(writer, line); err != nil {
			return err
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return writer.Flush()
}
