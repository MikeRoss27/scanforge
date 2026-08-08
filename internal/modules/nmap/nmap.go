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

	concurrency := runCtx.NmapConcurrency
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}
	if concurrency > len(targets) {
		concurrency = len(targets)
	}

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		status   = "completed"
		scanErrs []error
	)
	sem := make(chan struct{}, concurrency)

	for i, target := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, target hostPorts) {
			defer wg.Done()
			defer func() { <-sem }()

			base := fmt.Sprintf("host-%04d", i+1)
			cmd := runner.Command{
				Name: m.binary,
				Args: []string{
					"-p", joinPorts(target.Ports),
					"-oX", filepath.Join(outputDir, base+".xml"),
					"-oN", filepath.Join(outputDir, base+".txt"),
					"-sV",
					"-T4",
				},
				Timeout:    1 * time.Hour,
				StdoutFile: filepath.Join(outputDir, base+".stdout.log"),
				StderrFile: filepath.Join(outputDir, base+".stderr.log"),
			}
			if ip := net.ParseIP(target.Host); ip != nil && ip.To4() == nil {
				cmd.Args = append(cmd.Args, "-6")
			}
			cmd.Args = append(cmd.Args, target.Host)

			if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, cmd); err != nil {
				mu.Lock()
				scanErrs = append(scanErrs, fmt.Errorf("failed to write commands log for host %q: %w", target.Host, err))
				mu.Unlock()
				return
			}

			res, err := executor.Run(ctx, cmd)
			if err != nil {
				mu.Lock()
				scanErrs = append(scanErrs, fmt.Errorf("failed to run command %q for host %q: %w", cmd.Name, target.Host, err))
				mu.Unlock()
				return
			}
			if res.ExitCode != 0 {
				mu.Lock()
				status = fmt.Sprintf("failed (exit code %d)", res.ExitCode)
				mu.Unlock()
			}
		}(i, target)
	}
	wg.Wait()

	if len(scanErrs) > 0 {
		return nil, errors.Join(scanErrs...)
	}

	if err := addArtifact(runCtx); err != nil {
		return nil, fmt.Errorf("failed to publish nmap results: %w", err)
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
			if (char < 'a' || char > 'z') &&
				(char < 'A' || char > 'Z') &&
				(char < '0' || char > '9') &&
				char != '-' {
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

func completedResult(name string) *modules.Result {
	return &modules.Result{
		Name:   name,
		Status: "completed",
		OutputFiles: map[string]string{
			"nmap_xml": "03_ports/nmap",
		},
	}
}
