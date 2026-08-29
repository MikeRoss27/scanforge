// Package dnsbrute wraps the shuffledns tool for DNS bruteforcing.
package dnsbrute

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/dependencies"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

// maxBruteforceDomains caps how many discovered domains are brute-forced in
// one run: each domain is permuted with the whole wordlist, so N domains
// means N×wordlist massdns queries. Beyond this, the first ones found are
// kept and the rest skipped instead of exploding scan time.
const maxBruteforceDomains = 10

type Module struct {
	binary string
}

func New(binary string) *Module {
	if binary == "" {
		binary = "shuffledns"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string        { return "dnsbrute" }
func (m *Module) Description() string { return "DNS bruteforce with shuffledns and massdns" }
func (m *Module) Requires() []string  { return []string{"subdomains"} }
func (m *Module) Produces() []string  { return []string{"brute_subdomains"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	inputArt, err := runCtx.MustArtifact("subdomains")
	if err != nil {
		return nil, err
	}
	inputFile := runCtx.Run.Path(inputArt.Path)

	// shuffledns' -d flag takes domains (comma-separated), never a file:
	// passing the artifact path verbatim makes it fail with exit 1.
	domains, err := readDomains(inputFile)
	if err != nil {
		return nil, err
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("no domains to brute-force (subdomains artifact is empty)")
	}

	wordlist := resolveWordlist()
	if !runCtx.DryRun {
		if wordlist == "" {
			return nil, fmt.Errorf("no DNS wordlist found (checked: %s); install SecLists or set SCANFORGE_DNS_WORDLIST", strings.Join(dependencies.DNSWordlistPaths(), ", "))
		}
		if _, err := os.Stat(wordlist); os.IsNotExist(err) {
			return nil, fmt.Errorf("wordlist not found: %s", wordlist)
		}
	} else if wordlist == "" {
		wordlist = "<wordlist: none found>"
	}

	// massdns cannot run without a resolvers list: shuffledns would fail
	// with an unhelpful error, so fail fast with an actionable message when
	// none can be found.
	resolvers := resolveResolversFile()
	if !runCtx.DryRun {
		if resolvers == "" {
			return nil, fmt.Errorf("no DNS resolvers file found; checked: %s", strings.Join(resolverCandidates, ", "))
		}
	} else if resolvers == "" {
		resolvers = "<resolvers: none found>"
	}

	outputFile := runCtx.Run.Path("01_subdomains", "brute.txt")
	stderrFile := runCtx.Run.Path("00_meta", "dnsbrute.stderr.log")

	cmd := runner.Command{
		Name: m.binary,
		Args: []string{
			"-d", strings.Join(domains, ","),
			"-w", wordlist,
			"-r", resolvers,
			"-mode", "bruteforce",
			"-silent",
		},
		Timeout:    10 * time.Minute,
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

	if err := runCtx.AddArtifact("brute_subdomains", modules.Artifact{
		Name:   "brute_subdomains",
		Type:   "text",
		Path:   "01_subdomains/brute.txt",
		Scoped: true,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish bruteforce results: %w", err)
	}

	status := "completed"
	if res.ExitCode != 0 {
		status = fmt.Sprintf("failed (exit code %d)", res.ExitCode)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: status,
		OutputFiles: map[string]string{
			"brute_subdomains": "01_subdomains/brute.txt",
			"dnsbrute_stderr":  "00_meta/dnsbrute.stderr.log",
		},
	}, nil
}

// resolverCandidates are searched in order for a massdns-compatible
// resolvers list (one IP per line).
var resolverCandidates = []string{
	"/etc/dnsmasq-resolv.conf",
	"/run/systemd/resolve/resolv.conf",
	"/etc/resolv.conf",
	"/usr/share/seclists/Discovery/DNS/resolvers.txt",
	"/opt/SecLists/Discovery/DNS/resolvers.txt",
}

// resolveResolversFile returns the first resolvers file that exists and has
// at least one usable line, or "".
func resolveResolversFile() string {
	for _, candidate := range resolverCandidates {
		data, err := os.ReadFile(candidate)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			ip := strings.TrimSpace(line)
			if ip != "" && !strings.HasPrefix(ip, "#") {
				return candidate
			}
		}
	}
	return ""
}

// readDomains returns the trimmed, de-duplicated, non-empty lines of the
// subdomains artifact. The list is capped so a large subdomain discovery can
// never fan out into tens of thousands of wordlist permutations.
func readDomains(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read subdomains artifact: %w", err)
	}
	defer func() { _ = file.Close() }()

	seen := make(map[string]bool)
	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain == "" || seen[domain] {
			continue
		}
		seen[domain] = true
		domains = append(domains, domain)
		if len(domains) >= maxBruteforceDomains {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read subdomains artifact: %w", err)
	}
	return domains, nil
}

func resolveWordlist() string {
	for _, candidate := range dependencies.DNSWordlistPaths() {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}
