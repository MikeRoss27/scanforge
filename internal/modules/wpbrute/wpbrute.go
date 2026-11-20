// Package wpbrute is the opt-in-only credential probe of the WordPress chain.
// It is OFF by default everywhere including the wp preset. It refuses to run
// without: (1) --wp-bruteforce, (2) a confirmed scope (implicit scope
// requires --confirm-scope), (3) an explicit password wordlist with
// --wp-passwords, (4) at least one enumerated username from wpusers. It stops
// the moment wp-login.php (or the response body) shows a lockout, and never
// exceeds --wp-bruteforce-max attempts per user. No password list is bundled.
package wpbrute

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/modules/wpcore"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

const (
	outputRel      = "06_vulns/wp-brute.jsonl"
	reportName     = "wp_brute"
	usersFile      = wpcore.OutputDir + "/wp-users.jsonl"
	requestTimeout = 15 * time.Second
	maxBodyBytes   = 256 * 1024
	maxHosts       = 20
	maxUsers       = 20
	pageSleep      = 100 * time.Millisecond
)

type Finding struct {
	URL             string `json:"url"`
	Username        string `json:"username"`
	Method          string `json:"method"`
	Success         bool   `json:"success"`
	Attempts        int    `json:"attempts"`
	LockoutDetected bool   `json:"lockout_detected"`
}

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return "wpbrute" }
func (m *Module) Description() string {
	return "Opt-in credential probe against wp-login.php / XML-RPC for enumerated users (requires --wp-bruteforce and --wp-passwords)"
}
func (m *Module) Requires() []string     { return []string{"wp_fingerprint"} }
func (m *Module) SoftRequires() []string { return []string{"wp_users"} }
func (m *Module) Produces() []string     { return []string{reportName} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, _ runner.Executor) (*modules.Result, error) {
	if !runCtx.WordPress.Bruteforce {
		runCtx.EmitWarning("wpbrute: disabled (no --wp-bruteforce); nothing attempted")
		if err := writeFindings(runCtx.Run.Path(outputRel), nil); err != nil {
			return nil, err
		}
		return finishSkipped(m, runCtx)
	}
	if runCtx.WordPress.PasswordsFile == "" {
		return nil, fmt.Errorf("wpbrute: --wp-passwords is required when --wp-bruteforce is set (no password list is bundled)")
	}
	maxAttempts := runCtx.WordPress.BruteMax
	if maxAttempts <= 0 {
		maxAttempts = 100
	} else if maxAttempts > 1000 {
		runCtx.EmitWarning(fmt.Sprintf("wpbrute: --wp-bruteforce-max %d exceeds safety cap; using 1000", maxAttempts))
		maxAttempts = 1000
	}

	users, err := loadUsers(runCtx.Run.Path(usersFile), maxUsers)
	if err != nil {
		return nil, fmt.Errorf("wpbrute: cannot read wp_users: %w", err)
	}
	if len(users) == 0 {
		// Guard 4: no confirmed usernames, no brute force.
		return nil, fmt.Errorf("wpbrute: no usernames were enumerated (wpusers produced nothing); refusing to brute force blindly")
	}
	fpArt, err := runCtx.MustArtifact("wp_fingerprint")
	if err != nil {
		return nil, err
	}
	hosts, err := wpcore.LoadFingerprint(runCtx.Run.Path(fpArt.Path))
	if err != nil {
		return nil, fmt.Errorf("failed to read wp_fingerprint: %w", err)
	}

	passwords, err := loadWordlist(runCtx.WordPress.PasswordsFile)
	if err != nil {
		return nil, fmt.Errorf("wpbrute: cannot read --wp-passwords: %w", err)
	}
	if len(passwords) == 0 {
		return nil, fmt.Errorf("wpbrute: --wp-passwords %q contains no usable passwords", runCtx.WordPress.PasswordsFile)
	}
	if maxHosts > 0 && len(hosts) > maxHosts {
		hosts = hosts[:maxHosts]
	}
	method := strings.ToLower(strings.TrimSpace(runCtx.WordPress.BruteMethod))
	if method == "" {
		method = "login"
	}
	if method != "login" && method != "xmlrpc" {
		return nil, fmt.Errorf("wpbrute: unknown --wp-brute-method %q (want login|xmlrpc)", method)
	}

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, runner.Command{
		Name: "wpbrute (native)",
		Args: []string{"-method", method, "-hosts", fmt.Sprintf("%d", len(hosts)), "-users", fmt.Sprintf("%d", len(users)), "-max-attempts", fmt.Sprintf("%d", maxAttempts)},
	}); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	if runCtx.DryRun {
		for _, host := range hosts {
			for _, user := range users {
				runCtx.EmitWarning(fmt.Sprintf("wpbrute (dry-run) would try up to %d passwords for %q on %s", min(len(passwords), maxAttempts), user.Login, host.Target))
			}
		}
		if err := writeFindings(runCtx.Run.Path(outputRel), nil); err != nil {
			return nil, err
		}
		return finish(m, runCtx)
	}

	client, closeConn, err := modules.NewProxyClient(runCtx.Proxy, requestTimeout)
	if err != nil {
		return nil, err
	}
	defer closeConn()
	noRedirect := &http.Client{Timeout: requestTimeout, Transport: client.Transport, CheckRedirect: modules.NoRedirectCheckRedirect}

	var findings []Finding
	for _, host := range hosts {
		for _, user := range users {
			finding := Finding{URL: host.Target, Username: user.Login, Method: method}
			attempts := 0
			for _, password := range passwords {
				if attempts >= maxAttempts {
					break
				}
				if ctx.Err() != nil {
					break
				}
				attempts++
				ok, lockout := tryCredential(ctx, client, noRedirect, runCtx, host.Target, user.Login, password, method)
				if lockout {
					finding.LockoutDetected = true
					finding.Attempts = attempts
					findings = append(findings, finding)
					runCtx.EmitWarning(fmt.Sprintf("wpbrute: lockout detected on %s; stopping", host.Target))
					break
				}
				if ok {
					finding.Success = true
					finding.Attempts = attempts
					findings = append(findings, finding)
					runCtx.EmitFinding(modules.Finding{
						Module:   m.Name(),
						Severity: "critical",
						Title:    "WordPress credentials validated",
						Target:   host.Target,
						Detail:   user.Login,
					})
					break
				}
				if attempts == len(passwords) || attempts == maxAttempts {
					finding.Attempts = attempts
					findings = append(findings, finding)
					break
				}
				select {
				case <-ctx.Done():
				default:
					time.Sleep(pageSleep)
				}
			}
		}
	}

	sortFindings(findings)
	if err := writeFindings(runCtx.Run.Path(outputRel), findings); err != nil {
		return nil, err
	}
	return finish(m, runCtx)
}

func tryCredential(ctx context.Context, client, noRedirect *http.Client, runCtx *modules.RunContext, host, username, password, method string) (bool, bool) {
	switch method {
	case "xmlrpc":
		return tryXMLRPC(ctx, client, runCtx, host, username, password)
	default:
		return tryWPLogin(ctx, noRedirect, runCtx, host, username, password)
	}
}

func lockoutDetected(status int, body []byte) bool {
	if status == http.StatusTooManyRequests {
		return true
	}
	lower := strings.ToLower(string(body))
	for _, marker := range []string{"locked out", "too many failed", "too many login", "rate limit", "brute force"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func tryWPLogin(ctx context.Context, client *http.Client, runCtx *modules.RunContext, host, username, password string) (bool, bool) {
	target := host + "/wp-login.php"
	form := url.Values{
		"log":         {username},
		"pwd":         {password},
		"wp-submit":   {"Log In"},
		"redirect_to": {"/wp-admin/"},
		"testcookie":  {"1"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return false, false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	modules.ApplyHeaders(req, runCtx.Headers)

	resp, err := client.Do(req)
	if err != nil {
		return false, false
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if lockoutDetected(resp.StatusCode, body) {
		return false, true
	}
	for _, cookie := range resp.Cookies() {
		if strings.HasPrefix(cookie.Name, "wordpress_logged_in_") || cookie.Name == "wordpress_logged_in" {
			return true, false
		}
	}
	if resp.StatusCode == http.StatusFound {
		loc := resp.Header.Get("Location")
		if strings.Contains(loc, "wp-admin") && !strings.Contains(loc, "wp-login.php") {
			return true, false
		}
		return false, false
	}
	return false, false
}

func tryXMLRPC(ctx context.Context, client *http.Client, runCtx *modules.RunContext, host, username, password string) (bool, bool) {
	target := host + "/xmlrpc.php"
	payload := fmt.Sprintf(`<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>%s</string></value></param><param><value><string>%s</string></value></param></params></methodCall>`,
		xmlEscape(username), xmlEscape(password))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(payload))
	if err != nil {
		return false, false
	}
	req.Header.Set("Content-Type", "text/xml")
	modules.ApplyHeaders(req, runCtx.Headers)

	resp, err := client.Do(req)
	if err != nil {
		return false, false
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if lockoutDetected(resp.StatusCode, body) {
		return false, true
	}
	lower := strings.ToLower(string(body))
	if strings.Contains(lower, "faultcode") || strings.Contains(lower, "incorrect username") {
		return false, false
	}
	if strings.Contains(lower, "isadmin") {
		return true, false
	}
	return false, false
}

func xmlEscape(value string) string {
	replacements := [][2]string{
		{"&", "&amp;"},
		{"<", "&lt;"},
		{">", "&gt;"},
		{"\"", "&quot;"},
	}
	out := value
	for _, pair := range replacements {
		out = strings.ReplaceAll(out, pair[0], pair[1])
	}
	return out
}

// loadUsers reads the wp_users artifact (JSONL) and returns the enumerated
// logins, least-surprising first (file order).
func loadUsers(path string, maxUsers int) ([]struct{ Login string }, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var users []struct{ Login string }
	seen := map[string]struct{}{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var record struct {
			Login string `json:"login"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		login := strings.ToLower(strings.TrimSpace(record.Login))
		if login == "" {
			continue
		}
		if _, dup := seen[login]; dup {
			continue
		}
		seen[login] = struct{}{}
		users = append(users, struct{ Login string }{Login: login})
		if maxUsers > 0 && len(users) >= maxUsers {
			break
		}
	}
	return users, nil
}

func loadWordlist(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	out := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		password := strings.TrimRight(line, "\r\n")
		password = strings.TrimSuffix(password, "\n")
		if strings.TrimSpace(password) == "" {
			continue
		}
		if _, dup := seen[password]; dup {
			continue
		}
		seen[password] = struct{}{}
		out = append(out, password)
	}
	return out, nil
}

func sortFindings(items []Finding) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].URL == items[j].URL {
			return items[i].Username < items[j].Username
		}
		return items[i].URL < items[j].URL
	})
}

func finish(m *Module, runCtx *modules.RunContext) (*modules.Result, error) {
	if err := runCtx.AddArtifact(reportName, modules.Artifact{
		Name: reportName,
		Type: "jsonl",
		Path: outputRel,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish wp_brute: %w", err)
	}
	return &modules.Result{
		Name:   m.Name(),
		Status: "completed",
		OutputFiles: map[string]string{
			reportName: outputRel,
		},
	}, nil
}

// finishSkipped records the skipped state without publishing the artifact's
// content marker; downstream consumers (report) treat an empty file the same
// as "attempted, no findings".
func finishSkipped(m *Module, runCtx *modules.RunContext) (*modules.Result, error) {
	if err := runCtx.AddArtifact(reportName, modules.Artifact{
		Name: reportName,
		Type: "jsonl",
		Path: outputRel,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish wp_brute: %w", err)
	}
	return &modules.Result{
		Name:   m.Name(),
		Status: "skipped",
		OutputFiles: map[string]string{
			reportName: outputRel,
		},
	}, nil
}

func writeFindings(path string, items []Finding) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create WordPress brute force directory: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create WordPress brute force file: %w", err)
	}
	defer func() { _ = file.Close() }()

	for _, item := range items {
		if err := json.NewEncoder(file).Encode(item); err != nil {
			return fmt.Errorf("failed to write WordPress brute force result: %w", err)
		}
	}
	return nil
}
