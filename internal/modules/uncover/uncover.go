// Package uncover wraps ProjectDiscovery's uncover tool, which queries
// internet-wide asset search engines (Shodan, Censys, Fofa, Hunter, ZoomEye,
// ...) for hosts matching the scan target, instead of probing the target
// itself. It is genuinely gated on configuration: without at least one
// configured provider API key (internal/auth), uncover has nothing to query
// and is skipped rather than failed.
//
// Results are published as the "uncover_hosts" scoped text artifact, so the
// central scope filter (RunContext.AddArtifact) drops anything outside the
// effective scope before naabu folds it into open_ports.
package uncover

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/auth"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

const (
	artifactName = "uncover_hosts"
	outputRel    = "03_ports/uncover.txt"
	rawOutputRel = "03_ports/uncover-raw.jsonl"
	stderrRel    = "00_meta/uncover.stderr.log"

	// maxUncoverHosts caps the number of host:port pairs kept after
	// de-duplication, mirroring asnmap's maxIPs capping style: a popular
	// target can have thousands of indexed assets, and naabu's merge should
	// not be handed an unbounded list.
	maxUncoverHosts = 500
)

// knownEngines are the uncover engine names that are already identical to
// the provider names internal/auth stores by convention (see `scanforge auth
// set shodan/chaos/github <key>` in internal/cli/auth.go). Only names
// confirmed to match 1:1 are translated; anything else configured under
// internal/auth is simply not passed to uncover's -e flag.
var knownEngines = map[string]struct{}{
	"shodan":  {},
	"censys":  {},
	"fofa":    {},
	"hunter":  {},
	"zoomeye": {},
}

type Module struct {
	binary string
}

func New(binary string) *Module {
	if binary == "" {
		binary = "uncover"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string { return "uncover" }
func (m *Module) Description() string {
	return "Internet-wide exposed-asset search via Shodan/Censys/Fofa/etc. (requires configured API keys)"
}
func (m *Module) Requires() []string { return nil }
func (m *Module) Produces() []string { return []string{artifactName} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	outputPath := runCtx.Run.Path(outputRel)
	rawPath := runCtx.Run.Path(rawOutputRel)
	stderrPath := runCtx.Run.Path(stderrRel)
	result := &modules.Result{
		Name:   m.Name(),
		Status: "completed",
		OutputFiles: map[string]string{
			artifactName:     outputRel,
			"uncover_stderr": stderrRel,
		},
	}

	cfg, err := auth.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load auth config: %w", err)
	}
	engines := configuredEngines(cfg)
	if len(engines) == 0 {
		if err := publish(runCtx, outputPath, nil); err != nil {
			return nil, err
		}
		return modules.SkipNotApplicable(result, nil, "no search-engine API key configured (see `scanforge auth set <provider> <key>`)")
	}

	domain, err := modules.TargetHost(runCtx.Target)
	if err != nil {
		return nil, err
	}
	// uncover's domain search (-q <domain>) has nothing to match against a
	// bare IP; naabu's own active port scan already covers that case.
	if net.ParseIP(domain) != nil {
		if err := publish(runCtx, outputPath, nil); err != nil {
			return nil, err
		}
		return modules.SkipNotApplicable(result, nil, "target is an IP address, no asset search query to run")
	}

	// Conservative, conventional ProjectDiscovery flags: -q is the search
	// query (a bare domain triggers uncover's own domain-matching logic
	// across engines), -json for parseable output, -e picks engines, -o
	// writes the raw JSON lines, -silent suppresses banner/progress noise.
	cmd := runner.Command{
		Name:       m.binary,
		Args:       []string{"-q", domain, "-e", strings.Join(engines, ","), "-json", "-silent", "-o", rawPath},
		Timeout:    3 * time.Minute,
		StderrFile: stderrPath,
	}

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, cmd); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	res, err := executor.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run command %q: %w", cmd.Name, err)
	}

	if runCtx.DryRun {
		// The dry-run executor never touches rawPath: publish an empty
		// result instead of parsing a file that was never written.
		if err := publish(runCtx, outputPath, nil); err != nil {
			return nil, err
		}
		return result, nil
	}

	hosts, capped, err := parseHostPorts(rawPath, maxUncoverHosts)
	if err != nil {
		return nil, fmt.Errorf("failed to parse uncover output: %w", err)
	}
	if capped {
		runCtx.EmitWarning(fmt.Sprintf("uncover: result capped at %d host:port entries", maxUncoverHosts))
	}
	if err := publish(runCtx, outputPath, hosts); err != nil {
		return nil, err
	}

	status := "completed"
	if res.ExitCode != 0 {
		status = modules.FailureStatus(res.ExitCode, stderrPath)
	}
	result.Status = status
	if len(hosts) == 0 && res.ExitCode == 0 {
		return modules.SkipNotApplicable(result, nil, "no internet-wide assets found")
	}
	return result, nil
}

// configuredEngines returns the sorted, de-duplicated uncover engine names
// for which auth.Load() found a non-empty api_key, limited to the engines
// known to use the same name as scanforge's own provider convention.
func configuredEngines(cfg *auth.AuthConfig) []string {
	var engines []string
	for provider, keys := range cfg.Providers {
		if keys["api_key"] == "" {
			continue
		}
		if _, ok := knownEngines[provider]; !ok {
			continue
		}
		engines = append(engines, provider)
	}
	sort.Strings(engines)
	return engines
}

func publish(runCtx *modules.RunContext, path string, hosts []string) error {
	content := ""
	if len(hosts) > 0 {
		content = strings.Join(hosts, "\n") + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write uncover hosts: %w", err)
	}
	if err := runCtx.AddArtifact(artifactName, modules.Artifact{
		Name:   artifactName,
		Type:   "text",
		Path:   outputRel,
		Scoped: true,
	}); err != nil {
		return fmt.Errorf("failed to publish uncover hosts: %w", err)
	}
	return nil
}

type uncoverRecord struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
	Host string `json:"host"`
}

// parseHostPorts reads uncover's JSON-lines output and builds de-duplicated
// "host:port" (preferring the host field when present and non-empty, else
// the ip field) lines, capped at max. Malformed lines are skipped rather
// than failing the whole parse, since one bad line from a flaky engine
// should not lose every other result.
func parseHostPorts(path string, max int) (hosts []string, capped bool, err error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	defer func() { _ = file.Close() }()

	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec uncoverRecord
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		host := strings.TrimSpace(rec.Host)
		if host == "" {
			host = strings.TrimSpace(rec.IP)
		}
		if host == "" || rec.Port <= 0 || rec.Port > 65535 {
			continue
		}
		entry := net.JoinHostPort(host, strconv.Itoa(rec.Port))
		if _, ok := seen[entry]; ok {
			continue
		}
		seen[entry] = struct{}{}
		hosts = append(hosts, entry)
		if len(hosts) >= max {
			capped = true
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, false, err
	}
	sort.Strings(hosts)
	return hosts, capped, nil
}
