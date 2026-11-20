// Package ffuf wraps the ffuf directory and file fuzzing tool.
package ffuf

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

// defaultWordlistCandidates are searched in order when no wordlist is
// configured, so an out-of-the-box run works on common distro layouts.
var defaultWordlistCandidates = []string{
	"/usr/share/wordlists/dirb/common.txt",
	"/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
	"/usr/share/seclists/Discovery/Web-Content/common.txt",
	"/opt/SecLists/Discovery/Web-Content/common.txt",
	"~/tools/dirb-common.txt",
}

// defaultConcurrency bounds how many ffuf processes run at once, mirroring
// nmap's worker pool: one host's wildcard/soft-404 catch-all must not starve
// every other host of fuzzing time.
const defaultConcurrency = 4

type Module struct {
	binary string
}

func New(binary string) *Module {
	if binary == "" {
		binary = "ffuf"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string        { return "ffuf" }
func (m *Module) Description() string { return "Fast web fuzzer written in Go" }
func (m *Module) Requires() []string  { return []string{"alive_urls"} }
func (m *Module) Produces() []string  { return []string{"discovered_paths"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	inputArt, err := runCtx.MustArtifact("alive_urls")
	if err != nil {
		return nil, err
	}

	hosts, err := readHosts(runCtx.Run.Path(inputArt.Path))
	if err != nil {
		if runCtx.DryRun && os.IsNotExist(err) {
			if err := addArtifact(runCtx); err != nil {
				return nil, fmt.Errorf("failed to publish discovered paths: %w", err)
			}
			return &modules.Result{Name: m.Name(), Status: "completed"}, nil
		}
		return nil, fmt.Errorf("failed to read alive hosts: %w", err)
	}

	opts := runCtx.Ffuf
	wordlist := resolveWordlist(opts.Wordlist)
	if !runCtx.DryRun {
		if wordlist == "" {
			return nil, fmt.Errorf("no ffuf wordlist found (checked: %s); install wordlists (e.g. 'sudo apt install wordlists') or pass --ffuf-wordlist <path>", strings.Join(defaultWordlistCandidates, ", "))
		}
		if _, err := os.Stat(wordlist); os.IsNotExist(err) {
			return nil, fmt.Errorf("wordlist not found: %s", wordlist)
		}
	} else if wordlist == "" {
		// Dry runs log the command even when no wordlist is installed; keep
		// the placeholder obvious instead of emitting an invalid "-w :FUZZ".
		wordlist = "<wordlist: none found>"
	}

	outputDir := runCtx.Run.Path("05_content", "ffuf")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create ffuf output directory: %w", err)
	}
	logDir := runCtx.Run.Path("00_meta", "ffuf")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create ffuf log directory: %w", err)
	}

	// One ffuf process per host instead of a single invocation fuzzing every
	// host through a ":URL" wordlist. ffuf's -ac auto-calibration (learning
	// a host's soft-404/wildcard response signature from randomized
	// nonexistent paths, so a catch-all vhost doesn't "discover" every word
	// in the wordlist) only calibrates reliably against a single -u target;
	// verified against a real wildcard subdomain that even -ac -ach left
	// completely unfiltered when hosts were combined into one multi-wordlist
	// run, while the identical wordlist against a lone -u target filtered
	// perfectly. Fanning out per host is the only way to get a calibration
	// that actually holds per host, at the cost of several processes
	// instead of one (bounded by defaultConcurrency, same tradeoff nmap
	// already makes).
	concurrency := defaultConcurrency
	if concurrency > len(hosts) {
		concurrency = len(hosts)
	}

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		status   = "completed"
		scanErrs []error
	)
	outputs := make([]string, len(hosts))
	sem := make(chan struct{}, maxInt(concurrency, 1))
	completed := 0

	for i, host := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, host string) {
			defer wg.Done()
			defer func() { <-sem }()
			// ffuf's own JSON writer only flushes once a host's whole
			// wordlist pass finishes, so there is no finer-grained signal to
			// report mid-host; without this, a slow host (large wordlist, a
			// throttling WAF) looks indistinguishable from a hung one for
			// however long that host takes.
			defer func() {
				mu.Lock()
				completed++
				n := completed
				mu.Unlock()
				runCtx.EmitProgress(modules.ModuleProgressEvent{
					Name: m.Name(), Current: n, Total: len(hosts), Unit: "hosts",
				})
			}()

			base := fmt.Sprintf("host-%04d", i+1)
			perHostOut := filepath.Join(outputDir, base+".json")
			outputs[i] = perHostOut

			args := []string{
				"-w", fmt.Sprintf("%s:FUZZ", wordlist),
				"-u", host + "/FUZZ",
				"-o", perHostOut,
				"-of", "json",
				"-mc", "200,301,302,403",
				"-ac",
			}
			if opts.FilterCodes != "" {
				args = append(args, "-fc", opts.FilterCodes)
			}
			args = append(args, runCtx.ProxyArgs("-x")...)
			args = append(args, runCtx.HeaderArgs("-H")...)

			cmd := runner.Command{
				Name:       m.binary,
				Args:       args,
				Timeout:    1 * time.Hour,
				StdoutFile: filepath.Join(logDir, base+".stdout.log"),
				StderrFile: filepath.Join(logDir, base+".stderr.log"),
			}

			if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, cmd); err != nil {
				mu.Lock()
				scanErrs = append(scanErrs, fmt.Errorf("failed to write commands log for host %q: %w", host, err))
				mu.Unlock()
				return
			}

			res, err := executor.Run(ctx, cmd)
			if err != nil {
				mu.Lock()
				scanErrs = append(scanErrs, fmt.Errorf("failed to run command %q for host %q: %w", cmd.Name, host, err))
				mu.Unlock()
				return
			}
			if res.ExitCode != 0 {
				mu.Lock()
				status = fmt.Sprintf("failed (exit code %d)", res.ExitCode)
				mu.Unlock()
			}
		}(i, host)
	}
	wg.Wait()

	// Merge whatever per-host results exist even if one host's fuzz failed
	// or timed out: a single bad host must not discard every other host's
	// discovered paths from the report.
	finalOutput := runCtx.Run.Path("05_content", "ffuf.json")
	if err := mergeResults(outputs, finalOutput); err != nil {
		scanErrs = append(scanErrs, fmt.Errorf("failed to merge ffuf results: %w", err))
	}

	artifactErr := addArtifact(runCtx)

	if len(scanErrs) > 0 || artifactErr != nil {
		if artifactErr != nil {
			scanErrs = append(scanErrs, fmt.Errorf("failed to publish discovered paths: %w", artifactErr))
		}
		return &modules.Result{
			Name:   m.Name(),
			Status: "partial",
			OutputFiles: map[string]string{
				"discovered_paths": "05_content/ffuf.json",
				"ffuf_logs":        "00_meta/ffuf",
			},
		}, errors.Join(scanErrs...)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: status,
		OutputFiles: map[string]string{
			"discovered_paths": "05_content/ffuf.json",
			"ffuf_logs":        "00_meta/ffuf",
		},
	}, nil
}

func addArtifact(runCtx *modules.RunContext) error {
	return runCtx.AddArtifact("discovered_paths", modules.Artifact{
		Name: "discovered_paths",
		Type: "json",
		Path: "05_content/ffuf.json",
	})
}

// readHosts reads one alive host URL per line, same format naabu/httpx and
// every other alive_urls consumer already expects.
func readHosts(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var hosts []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		hosts = append(hosts, line)
	}
	return hosts, scanner.Err()
}

// ffufDocument is the subset of ffuf's native JSON output this module cares
// about: the array of per-result objects. Each result is kept as raw JSON so
// merging doesn't need to know ffuf's full result schema.
type ffufDocument struct {
	Results []json.RawMessage `json:"results"`
}

// mergeResults combines every per-host ffuf.json into the single
// discovered_paths artifact the rest of the pipeline (report parsers,
// attacksurface) already expects. A missing or malformed per-host file
// (process never ran under a dry-run/fake executor, or crashed before
// writing) is skipped rather than failing the whole merge.
func mergeResults(paths []string, out string) error {
	merged := ffufDocument{Results: []json.RawMessage{}}
	for _, path := range paths {
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var doc ffufDocument
		if err := json.Unmarshal(data, &doc); err != nil {
			continue
		}
		merged.Results = append(merged.Results, doc.Results...)
	}
	data, err := json.Marshal(merged)
	if err != nil {
		return err
	}
	return os.WriteFile(out, data, 0644)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// resolveWordlist returns the configured wordlist (with ~ expanded) or, when
// none is set, the first default candidate that exists on disk.
func resolveWordlist(configured string) string {
	if configured != "" {
		return expandPath(configured)
	}
	for _, candidate := range defaultWordlistCandidates {
		path := expandPath(candidate)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// expandPath resolves a leading ~ to the current user's home directory.
func expandPath(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~"))
		}
	}
	return path
}
