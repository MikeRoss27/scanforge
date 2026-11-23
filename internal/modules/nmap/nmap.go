// Package nmap wraps the nmap port scanner, running hosts in parallel with a
// bounded worker pool.
package nmap

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

// defaultConcurrency bounds how many nmap processes run at once when the
// caller doesn't set RunContext.NmapConcurrency. Kept conservative: full
// -sV scans are CPU/network heavy, and running too many in parallel makes
// scans noisier (more simultaneous connections) than a pentester may want.
const defaultConcurrency = 4

// maxPortsPerCommand caps how many ports one nmap invocation scans. A single
// -p list with hundreds of ports pushes past ARG_MAX on some systems and
// slows the host's own TCP stack down, so oversized lists are chunked into
// several per-host scans instead.
const maxPortsPerCommand = 250

type Module struct {
	binary string
}

func New(binary string) *Module {
	if binary == "" {
		binary = "nmap"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string        { return "nmap" }
func (m *Module) Description() string { return "Network exploration tool and security / port scanner" }
func (m *Module) Requires() []string  { return []string{"open_ports"} }
func (m *Module) Produces() []string  { return []string{"nmap_xml"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	inputArt, err := runCtx.MustArtifact("open_ports")
	if err != nil {
		return nil, err
	}

	targets, err := readOpenPorts(runCtx.Run.Path(inputArt.Path))
	if err != nil {
		if runCtx.DryRun && os.IsNotExist(err) {
			if err := addArtifact(runCtx); err != nil {
				return nil, fmt.Errorf("failed to publish nmap results: %w", err)
			}
			return completedResult(m.Name()), nil
		}
		return nil, fmt.Errorf("failed to parse open ports: %w", err)
	}

	outputDir := runCtx.Run.Path("03_ports", "nmap")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create nmap output directory: %w", err)
	}

	// Several hostnames often front the exact same backend (a bare domain
	// and its "www." alias resolving to one IP is the common case): naabu
	// records open ports per hostname, so without this step nmap would
	// run a full -sV + NSE scan against the identical server once per
	// alias - doubling scan time and probe noise against the target for
	// zero extra information. hostIPs reuses dnsx's own resolution (never
	// a fresh DNS lookup here) so the grouping below only ever merges
	// hosts proven identical; when that data isn't available (dnsx_raw
	// not published, e.g. in unit tests) every host gets its own group,
	// which is exactly today's behavior.
	hostIndex := make(map[string]int, len(targets))
	for i, target := range targets {
		hostIndex[target.Host] = i
	}
	hostIPs := map[string]string{}
	if art, ok := runCtx.GetArtifact("dnsx_raw"); ok {
		hostIPs = loadHostIPs(runCtx.Run.Path(art.Path))
	}
	groups := groupTargets(targets, hostIPs)

	concurrency := runCtx.NmapConcurrency
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}
	if concurrency > len(groups) {
		concurrency = len(groups)
	}

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		status   = "completed"
		scanErrs []error
	)
	sem := make(chan struct{}, concurrency)
	progress := newScanProgress(m.Name(), len(targets), runCtx.EmitProgress)
	addErr := func(err error) {
		mu.Lock()
		scanErrs = append(scanErrs, err)
		mu.Unlock()
	}

	for _, group := range groups {
		if len(group.Hosts) > 1 {
			runCtx.EmitWarning(group.dedupNote())
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(group hostGroup) {
			defer wg.Done()
			defer func() { <-sem }()
			// Every host in the group - leader and aliases alike - counts
			// toward the live "X of N hosts" progress exactly once,
			// whatever path this goroutine returns through (success or a
			// log/exec failure partway through a chunk).
			defer func() {
				for range group.Hosts {
					progress.hostDone()
				}
			}()

			leader := group.Hosts[0]
			leaderIdx := hostIndex[leader]
			chunks := chunkPorts(group.Ports)

			for ci, chunk := range chunks {
				leaderBase := chunkBase(leaderIdx, ci, len(chunks))
				cmd := runner.Command{
					Name: m.binary,
					Args: []string{
						"-p", joinPorts(chunk),
						"-oX", filepath.Join(outputDir, leaderBase+".xml"),
						"-oN", filepath.Join(outputDir, leaderBase+".txt"),
						"-sV",
						"-T4",
						// Periodic "About NN% done" lines on stdout feed
						// the live progress line; a -sV scan can sit for
						// minutes without any other visible output.
						"--stats-every", statsEvery,
					},
					Timeout:    1 * time.Hour,
					StdoutFile: filepath.Join(outputDir, leaderBase+".stdout.log"),
					StderrFile: filepath.Join(outputDir, leaderBase+".stderr.log"),
				}
				if ip := net.ParseIP(leader); ip != nil && ip.To4() == nil {
					cmd.Args = append(cmd.Args, "-6")
				}
				cmd.Args = append(cmd.Args, leader)

				if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, cmd); err != nil {
					addErr(fmt.Errorf("failed to write commands log for host %q: %w", leader, err))
					return
				}

				stop := make(chan struct{})
				tailDone := make(chan struct{})
				go func() {
					defer close(tailDone)
					modules.TailLines(cmd.StdoutFile, stop, time.Second, func(line string) {
						progress.observe(leaderBase, line)
					})
				}()
				res, err := executor.Run(ctx, cmd)
				close(stop)
				<-tailDone
				progress.jobDone(leaderBase)
				if err != nil {
					addErr(fmt.Errorf("failed to run command %q for host %q: %w", cmd.Name, leader, err))
					return
				}
				if res.ExitCode != 0 {
					mu.Lock()
					status = fmt.Sprintf("failed (exit code %d)", res.ExitCode)
					mu.Unlock()
				}

				// Every alias is backed by the exact same host nmap just
				// scanned: publish a copy of this chunk's result under
				// each alias's own name instead of re-scanning it.
				for _, alias := range group.Hosts[1:] {
					aliasBase := chunkBase(hostIndex[alias], ci, len(chunks))
					if err := publishAlias(
						filepath.Join(outputDir, leaderBase+".xml"), filepath.Join(outputDir, aliasBase+".xml"),
						filepath.Join(outputDir, leaderBase+".txt"), filepath.Join(outputDir, aliasBase+".txt"),
						leader, alias,
					); err != nil {
						addErr(fmt.Errorf("failed to publish shared scan result for alias host %q: %w", alias, err))
					}
				}
			}
		}(group)
	}
	wg.Wait()

	// Publish whatever XML files were written even if one host's scan
	// failed (timeout, host down, nmap crash): a single bad host must not
	// discard every other host's results from the report.
	artifactErr := addArtifact(runCtx)

	if len(scanErrs) > 0 || artifactErr != nil {
		if artifactErr != nil {
			scanErrs = append(scanErrs, fmt.Errorf("failed to publish nmap results: %w", artifactErr))
		}
		return &modules.Result{
			Name:   m.Name(),
			Status: "partial",
			OutputFiles: map[string]string{
				"nmap_xml": "03_ports/nmap",
			},
		}, errors.Join(scanErrs...)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: status,
		OutputFiles: map[string]string{
			"nmap_xml": "03_ports/nmap",
		},
	}, nil
}

func addArtifact(runCtx *modules.RunContext) error {
	return runCtx.AddArtifact("nmap_xml", modules.Artifact{
		Name: "nmap_xml",
		Type: "xml_collection",
		Path: "03_ports/nmap",
	})
}

type hostPorts struct {
	Host  string
	Ports []int
}

func readOpenPorts(path string) ([]hostPorts, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	portsByHost := make(map[string]map[int]struct{})
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		host, port, err := parseHostPort(line)
		if err != nil {
			return nil, err
		}
		if portsByHost[host] == nil {
			portsByHost[host] = make(map[int]struct{})
		}
		portsByHost[host][port] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	hosts := make([]string, 0, len(portsByHost))
	for host := range portsByHost {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	targets := make([]hostPorts, 0, len(hosts))
	for _, host := range hosts {
		ports := make([]int, 0, len(portsByHost[host]))
		for port := range portsByHost[host] {
			ports = append(ports, port)
		}
		sort.Ints(ports)
		targets = append(targets, hostPorts{Host: host, Ports: ports})
	}
	return targets, nil
}

func parseHostPort(value string) (string, int, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		lastColon := strings.LastIndexByte(value, ':')
		if lastColon < 1 {
			return "", 0, fmt.Errorf("invalid naabu entry %q: expected host:port", value)
		}
		host, portText = value[:lastColon], value[lastColon+1:]
		if strings.Contains(host, ":") && net.ParseIP(host) == nil {
			return "", 0, fmt.Errorf("invalid naabu entry %q: IPv6 addresses must be valid", value)
		}
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return "", 0, fmt.Errorf("invalid naabu entry %q: host is empty", value)
	}
	if net.ParseIP(host) == nil && !validHostname(host) {
		return "", 0, fmt.Errorf("invalid naabu entry %q: invalid host", value)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid naabu entry %q: port must be between 1 and 65535", value)
	}
	return host, port, nil
}

func validHostname(host string) bool {
	if len(host) > 253 {
		return false
	}
	host = strings.TrimSuffix(host, ".")
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			// '_' is technically non-conformant DNS but common in the wild
			// (_dmarc, _domainkey...); reject it here and nmap simply never
			// scans a legitimate in-scope host.
			if (char < 'a' || char > 'z') &&
				(char < 'A' || char > 'Z') &&
				(char < '0' || char > '9') &&
				char != '-' && char != '_' {
				return false
			}
		}
	}
	return true
}

func joinPorts(ports []int) string {
	values := make([]string, len(ports))
	for i, port := range ports {
		values[i] = strconv.Itoa(port)
	}
	return strings.Join(values, ",")
}

// chunkPorts splits a port list into batches of at most maxPortsPerCommand.
// chunkBase names a command's output files: "host-%04d" for a host scanned
// in one command, "host-%04d-%d" per chunk when its port list was split.
// hostIdx is the host's position in the original (pre-grouping) target
// list, so every hostname - leader or alias - keeps a stable, predictable
// filename regardless of which group it ended up sharing a scan with.
func chunkBase(hostIdx, chunkIdx, totalChunks int) string {
	if totalChunks > 1 {
		return fmt.Sprintf("host-%04d-%d", hostIdx+1, chunkIdx+1)
	}
	return fmt.Sprintf("host-%04d", hostIdx+1)
}

// The input stays sorted (readOpenPorts sorts it), so chunks are contiguous
// slices and the -p argument of every command remains deterministic.
func chunkPorts(ports []int) [][]int {
	if len(ports) <= maxPortsPerCommand {
		return [][]int{ports}
	}
	chunks := make([][]int, 0, (len(ports)+maxPortsPerCommand-1)/maxPortsPerCommand)
	for start := 0; start < len(ports); start += maxPortsPerCommand {
		end := start + maxPortsPerCommand
		if end > len(ports) {
			end = len(ports)
		}
		chunks = append(chunks, ports[start:end])
	}
	return chunks
}

func completedResult(name string) *modules.Result {
	return &modules.Result{
		Name:   name,
		Status: "completed",
		OutputFiles: map[string]string{
			"nmap_xml": "03_ports/nmap",
		},
	}
}
