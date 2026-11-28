// Package dnspermute wraps gotator to generate subdomain permutations
// (dev/staging/internal-style variants, numeric suffixes, word combinations)
// from the subdomains already discovered, so names that were never crawled,
// brute-forced from a static wordlist or logged in CT transparency still get
// a shot at being found. Candidates are unresolved until dnsx picks them up,
// exactly like dnsbrute's brute_subdomains.
package dnspermute

import (
	"bufio"
	"context"
	_ "embed"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

// wordlist is a small, built-in permutation dictionary (environment names,
// infra/service words, common prefixes/suffixes) embedded at build time so
// this module never depends on an external wordlist being installed, unlike
// dnsbrute's SecLists dependency.
//
//go:embed words.txt
var wordlist []byte

// maxPermuteSeedDomains caps how many already-discovered domains get
// permuted: each seed is combined with the whole wordlist (and with every
// other seed in -adv mode), so this bounds gotator's fan-out the same way
// dnsbrute caps its bruteforce domains.
const maxPermuteSeedDomains = 20

// maxPermutedCandidates caps how many permutation candidates are handed to
// dnsx for resolution, so one large seed list can never turn into tens of
// thousands of DNS queries downstream.
const maxPermutedCandidates = 5000

type Module struct {
	binary string
}

func New(binary string) *Module {
	if binary == "" {
		binary = "gotator"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string { return "dnspermute" }
func (m *Module) Description() string {
	return "Generates subdomain permutations (dev/staging/word-combination variants) with gotator"
}
func (m *Module) Requires() []string { return []string{"subdomains"} }
func (m *Module) Produces() []string { return []string{"permuted_subdomains"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	inputArt, err := runCtx.MustArtifact("subdomains")
	if err != nil {
		return nil, err
	}

	seeds, err := readSeeds(runCtx.Run.Path(inputArt.Path))
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

	seedFile := runCtx.Run.Path("01_subdomains", "permute-seeds.txt")
	wordlistFile := runCtx.Run.Path("01_subdomains", "permute-words.txt")
	rawOutputFile := runCtx.Run.Path("01_subdomains", "permute-raw.txt")
	outputFile := runCtx.Run.Path("01_subdomains", "permute.txt")
	stderrFile := runCtx.Run.Path("00_meta", "dnspermute.stderr.log")

	if !runCtx.DryRun {
		if err := os.WriteFile(seedFile, []byte(strings.Join(seeds, "\n")+"\n"), 0644); err != nil {
			return nil, fmt.Errorf("failed to write permutation seeds: %w", err)
		}
		if err := os.WriteFile(wordlistFile, wordlist, 0644); err != nil {
			return nil, fmt.Errorf("failed to write permutation wordlist: %w", err)
		}
	}

	cmd := runner.Command{
		Name: m.binary,
		Args: []string{
			"-sub", seedFile,
			"-perm", wordlistFile,
			"-depth", "1",
			"-mindup",
			"-adv",
			"-silent",
		},
		Timeout:    5 * time.Minute,
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
		if err := writeCandidates(rawOutputFile, outputFile, seeds); err != nil {
			return nil, fmt.Errorf("failed to derive permutation candidates: %w", err)
		}
	}

	if err := runCtx.AddArtifact("permuted_subdomains", modules.Artifact{
		Name:   "permuted_subdomains",
		Type:   "text",
		Path:   "01_subdomains/permute.txt",
		Scoped: true,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish permutation candidates: %w", err)
	}

	status := "completed"
	if res.ExitCode != 0 {
		status = modules.FailureStatus(res.ExitCode, stderrFile)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: status,
		OutputFiles: map[string]string{
			"permuted_subdomains": "01_subdomains/permute.txt",
			"dnspermute_stderr":   "00_meta/dnspermute.stderr.log",
		},
	}, nil
}

// readSeeds returns the trimmed, de-duplicated, non-empty lines of the
// subdomains artifact, capped so a large subdomain discovery can never fan
// out into an unbounded number of permutations.
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
		if len(seeds) >= maxPermuteSeedDomains {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read subdomains artifact: %w", err)
	}
	return seeds, nil
}

// writeCandidates de-duplicates gotator's output, drops lines identical to
// a seed (those are already resolved by the main subfinder→dnsx pass, so
// re-resolving them here would be wasted work) and caps the result at
// maxPermutedCandidates.
func writeCandidates(rawPath, outPath string, seeds []string) error {
	seedSet := make(map[string]struct{}, len(seeds))
	for _, s := range seeds {
		seedSet[s] = struct{}{}
	}

	input, err := os.Open(rawPath)
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()

	output, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer func() { _ = output.Close() }()

	seen := make(map[string]struct{})
	writer := bufio.NewWriter(output)
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	count := 0
	for scanner.Scan() && count < maxPermutedCandidates {
		line := strings.TrimSpace(scanner.Text())
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
