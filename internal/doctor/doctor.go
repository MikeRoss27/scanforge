// Package doctor validates that the tools required by a profile are installed
// and reachable.
package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/dependencies"
	"github.com/MikeRoss27/scanforge/internal/ui"
)

type Severity string

const (
	SeverityOK       Severity = "ok"
	SeverityWarn     Severity = "warn"
	SeverityFail     Severity = "fail"
	SeverityRequired Severity = "required"
)

type Check struct {
	Name     string   `json:"name"`
	Status   Severity `json:"status"`
	Message  string   `json:"message"`
	Required bool     `json:"required"`
}

type Options struct {
	Profile string
	JSON    bool
	Verbose bool
	Config  *config.Config
}

type ToolChecker interface {
	CheckTool(ctx context.Context, name, binary string, verbose bool) Check
}

type DefaultToolChecker struct{}

func (DefaultToolChecker) CheckTool(ctx context.Context, name, binary string, verbose bool) Check {
	check := Check{
		Name:     name,
		Required: true,
	}

	path, err := exec.LookPath(binary)
	if err != nil {
		check.Status = SeverityFail
		check.Message = fmt.Sprintf("not found in PATH (configured as %q)", binary)
		return check
	}

	versionOutput, versionErr := runVersionCommand(ctx, path)
	if versionErr != nil {
		check.Status = SeverityWarn
		check.Message = fmt.Sprintf("found at %s but version check failed: %v", path, versionErr)
		return check
	}

	check.Status = SeverityOK
	version := extractVersionLine(versionOutput)

	goModVersion := ""
	if name == "dnsx" || name == "tlsx" || name == "ffuf" {
		goModVersion = goModVersionForBinary(ctx, path, goModulePathForTool(name))
	}

	if verbose {
		if goModVersion != "" {
			check.Message = fmt.Sprintf("%s (%s; tool reports %s)", goModVersion, path, version)
		} else {
			check.Message = fmt.Sprintf("%s (%s)", version, path)
		}
	} else {
		if goModVersion != "" {
			check.Message = goModVersion
		} else {
			check.Message = version
		}
		if check.Message == "" {
			check.Message = path
		}
	}

	return check
}

func goModVersionForBinary(ctx context.Context, binaryPath, modulePath string) string {
	if modulePath == "" {
		return ""
	}
	goModOutput, err := runGoVersionCommand(ctx, binaryPath)
	if err != nil {
		return ""
	}
	return extractVersionFromGoMod(goModOutput, modulePath)
}

func goModulePathForTool(name string) string {
	switch name {
	case "dnsx":
		return "github.com/projectdiscovery/dnsx"
	case "tlsx":
		return "github.com/projectdiscovery/tlsx"
	case "ffuf":
		return "github.com/ffuf/ffuf/v2"
	default:
		return ""
	}
}

type Runner struct {
	checker ToolChecker
}

func New(checker ToolChecker) *Runner {
	if checker == nil {
		checker = DefaultToolChecker{}
	}
	return &Runner{checker: checker}
}

func (r *Runner) Run(ctx context.Context, opts Options) ([]Check, int, error) {
	cfg := opts.Config
	if cfg == nil {
		cfg = config.Default()
	}

	profile := opts.Profile
	if profile == "" {
		profile = cfg.DefaultProfile
	}

	checks := make([]Check, 0, 20)

	moduleNames, err := cfg.ProfileModules(profile)
	if err != nil {
		return nil, 1, err
	}
	moduleSet := make(map[string]bool, len(moduleNames))
	for _, m := range moduleNames {
		moduleSet[m] = true
	}

	for _, dependency := range dependencies.ForModules(moduleNames) {
		binary := cfg.ToolPath(dependency.Binary)
		if dependency.Name == "chromium" {
			binary = resolveBrowserBinary(binary)
		}
		check := r.checker.CheckTool(ctx, dependency.Name, binary, opts.Verbose)
		check.Required = !dependency.Optional
		switch check.Status {
		case SeverityFail:
			if dependency.Optional {
				check.Status = SeverityWarn
			}
			check.Message += "; install: " + dependencies.InstallHint(dependency)
		case SeverityOK:
			expected := ""
			if dependency.Compare {
				expected = dependencies.ExpectedVersion(dependency.VersionKey)
			}
			if expected != "" {
				if dependency.Name == "dnsx" || dependency.Name == "tlsx" || dependency.Name == "ffuf" {
					resolvedPath := binary
					if p, err := exec.LookPath(binary); err == nil {
						resolvedPath = p
					}
					modVersion := goModVersionForBinary(ctx, resolvedPath, goModulePathForTool(dependency.Name))
					if modVersion == "" {
						// Go not available or binary without module info — skip strict
						// comparison to avoid false positives from stale embedded version.
					} else if !strings.EqualFold(modVersion, strings.TrimPrefix(expected, "v")) {
						check.Status = SeverityWarn
						check.Message += fmt.Sprintf("; expected v%s (pinned in .tools-version)", expected)
					}
				} else if !versionMatches(check.Message, expected) {
					check.Status = SeverityWarn
					check.Message += fmt.Sprintf("; expected v%s (pinned in .tools-version)", expected)
				}
			}
		}
		checks = append(checks, check)
	}
	if moduleSet["dnsbrute"] {
		checks = append(checks, checkDNSWordlist())
	}

	checks = append(checks, checkWorkspace(cfg))
	checks = append(checks, checkConfigFile())
	checks = append(checks, checkScopeFile(cfg))

	exitCode := 0
	for _, check := range checks {
		if check.Required && check.Status == SeverityFail {
			exitCode = 1
		}
	}

	return checks, exitCode, nil
}

func resolveBrowserBinary(configured string) string {
	if configured != "" && configured != "chromium" {
		return configured
	}
	for _, candidate := range []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome-headless-shell"} {
		if path, err := exec.LookPath(candidate); err == nil {
			return path
		}
	}
	return configured
}

var semanticVersion = regexp.MustCompile(`(?i)\bv?([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9a-z.-]+)?)\b`)
var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func versionMatches(message, expected string) bool {
	match := semanticVersion.FindStringSubmatch(ansiEscape.ReplaceAllString(message, ""))
	return len(match) > 1 && strings.EqualFold(match[1], strings.TrimPrefix(expected, "v"))
}

func checkDNSWordlist() Check {
	for _, candidate := range dependencies.DNSWordlistPaths() {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Size() > 0 {
			return Check{Name: "dns-wordlist", Status: SeverityOK, Message: candidate, Required: true}
		}
	}
	return Check{
		Name:     "dns-wordlist",
		Status:   SeverityFail,
		Message:  "no compatible wordlist found; rerun install.sh --full, install SecLists, or set SCANFORGE_DNS_WORDLIST",
		Required: true,
	}
}

func checkWorkspace(cfg *config.Config) Check {
	dir := config.WorkspaceDir(cfg)
	check := Check{
		Name:     "workspace",
		Required: true,
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		check.Status = SeverityFail
		check.Message = fmt.Sprintf("unable to create %q: %v", dir, err)
		return check
	}

	testFile := filepath.Join(dir, ".doctor-write-test")
	if err := os.WriteFile(testFile, []byte("ok"), 0644); err != nil {
		check.Status = SeverityFail
		check.Message = fmt.Sprintf("directory %q is not writable: %v", dir, err)
		return check
	}
	_ = os.Remove(testFile)

	check.Status = SeverityOK
	check.Message = fmt.Sprintf("writable (%s)", dir)
	return check
}

func checkConfigFile() Check {
	check := Check{
		Name:     "config",
		Required: false,
	}

	path := config.ResolvePath("")
	if _, err := os.Stat(path); err != nil {
		check.Status = SeverityWarn
		check.Message = fmt.Sprintf("%s not found (run: scanforge init)", path)
		return check
	}

	if _, err := config.Load(path); err != nil {
		check.Status = SeverityFail
		check.Message = fmt.Sprintf("%s is invalid: %v", path, err)
		check.Required = false
		return check
	}

	check.Status = SeverityOK
	check.Message = path
	return check
}

func checkScopeFile(cfg *config.Config) Check {
	check := Check{
		Name:     "scope",
		Required: false,
	}

	path := cfg.DefaultScope
	if path == "" {
		path = config.DefaultScope
	}

	info, err := os.Stat(path)
	if err != nil {
		check.Status = SeverityWarn
		check.Message = fmt.Sprintf("%s not found (run: scanforge init)", path)
		return check
	}

	if info.Size() == 0 {
		check.Status = SeverityWarn
		check.Message = fmt.Sprintf("%s is empty", path)
		return check
	}

	check.Status = SeverityOK
	check.Message = path
	return check
}

func runVersionCommand(ctx context.Context, binary string) (string, error) {
	args := [][]string{
		{"--version"},
		{"-V"},
		{"-version"},
		{"-v"},
		{"version"},
	}

	var lastErr error
	for _, arg := range args {
		cmd := exec.CommandContext(ctx, binary, arg...)
		output, err := cmd.CombinedOutput()
		if err == nil {
			return string(output), nil
		}
		lastErr = err
	}

	return "", lastErr
}

func runGoVersionCommand(ctx context.Context, binary string) (string, error) {
	cmd := exec.CommandContext(ctx, "go", "version", "-m", binary)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

func extractVersionFromGoMod(output, modulePath string) string {
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "mod" && fields[1] == modulePath {
			return strings.TrimPrefix(fields[2], "v")
		}
		if strings.HasPrefix(line, "mod\t"+modulePath+"\t") {
			parts := strings.Split(line, "\t")
			if len(parts) >= 3 {
				return strings.TrimPrefix(parts[2], "v")
			}
		}
	}
	return ""
}

// extractVersionLine pulls the one meaningful line out of a tool's version
// output. Many of the wrapped binaries (projectdiscovery's tools especially)
// print a multi-line ASCII banner before the actual version, which would
// otherwise blow up every doctor/plan-style table row with garbage.
func extractVersionLine(output string) string {
	var lastNonEmpty string
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		lastNonEmpty = line
		if strings.Contains(strings.ToLower(line), "version") {
			return line
		}
	}
	return lastNonEmpty
}

func FormatChecks(checks []Check) string {
	var rows [][]string

	passed := 0
	failed := 0
	warned := 0

	for _, check := range checks {
		switch check.Status {
		case SeverityOK:
			passed++
		case SeverityWarn:
			warned++
		case SeverityFail:
			if check.Required {
				failed++
			}
		}
		rows = append(rows, []string{ui.StatusSymbol(string(check.Status)), check.Name, check.Message})
	}

	var b strings.Builder
	b.WriteString(ui.Table([]string{"", "CHECK", "DETAILS"}, rows))
	b.WriteString("\n")
	fmt.Fprintf(&b, "%d %s", passed, ui.Green("passed"))
	if failed > 0 {
		fmt.Fprintf(&b, ", %d %s", failed, ui.Red("failed"))
	}
	if warned > 0 {
		fmt.Fprintf(&b, ", %d %s", warned, ui.Yellow("warning(s)"))
	}
	b.WriteString("\n")

	return ui.PanelWith("🩺 DOCTOR", b.String(), ui.Accent, ui.Accent)
}

func FormatChecksJSON(checks []Check) (string, error) {
	data, err := json.MarshalIndent(checks, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
