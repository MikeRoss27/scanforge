// Package payloadgen derives contextual fuzzing payloads from the scan's
// own findings: API endpoints discovered in JavaScript, parameters harvested
// from historical URLs, and technology-specific endpoints. The generated
// wordlists are published as artifacts for reuse in ffuf, nuclei custom
// templates or manual testing.
package payloadgen

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

const (
	outputDir = "04_payloads"

	fileAPIPaths      = "api-paths.txt"
	fileAPIEndpoints  = "api-endpoints.txt"
	fileParameters    = "parameters.txt"
	fileTechEndpoints = "tech-endpoints.txt"
	fileManifest      = "manifest.jsonl"
)

// techEndpoints maps a technology keyword to well-known paths worth probing.
var techEndpoints = map[string][]string{
	"wordpress":  {"wp-login.php", "wp-admin/", "wp-json/wp/v2/users", "xmlrpc.php", "wp-content/debug.log"},
	"drupal":     {"CHANGELOG.txt", "core/install.php", "admin/", "user/login", "update.php"},
	"joomla":     {"administrator/", "configuration.php~", "index.php?option=com_users"},
	"django":     {"admin/", "api-auth/", "graphql", "media/", "static/"},
	"rails":      {"rails/info", "assets/application.js", "admin/", "graphql"},
	"laravel":    {"_ignition/health-check", "_ignition/execute-solution", "api/", "storage/logs/laravel.log"},
	"spring":     {"actuator", "actuator/health", "actuator/env", "actuator/beans", "swagger-ui/", "v3/api-docs"},
	"grafana":    {"api/health", "api/dashboards", "login"},
	"kibana":     {"api/status", "app/discover"},
	"jenkins":    {"script", "api/json", "login", "cli"},
	"phpmyadmin": {"index.php"},
	"gitlab":     {"api/v4/projects", "users/sign_in", ".well-known/security.txt"},
	"confluence": {"/rest/api/content", "login.action"},
	"jira":       {"rest/api/2/serverInfo", "secure/Dashboard.jspa", "browse"},
}

// ManifestEntry describes one generated wordlist.
type ManifestEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return "payloadgen" }
func (m *Module) Description() string {
	return "Generates contextual wordlists (API paths, parameters, tech endpoints) from scan findings"
}
func (m *Module) Requires() []string { return []string{"alive_urls"} }
func (m *Module) Produces() []string { return []string{"payload_wordlists"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, _ runner.Executor) (*modules.Result, error) {
	var apiPaths []string
	var apiEndpoints []string
	var parameters []string
	var techs []string

	if art, ok := runCtx.GetArtifact("js_secrets"); ok {
		endpoints, err := readJSEndpoints(runCtx.Run.Path(art.Path))
		if err != nil {
			return nil, fmt.Errorf("failed to read JS endpoints: %w", err)
		}
		for _, endpoint := range endpoints {
			apiEndpoints = append(apiEndpoints, endpoint)
			if path := endpointPath(endpoint); path != "" {
				apiPaths = append(apiPaths, path)
				apiPaths = append(apiPaths, path+".json")
			}
		}
	}

	if art, ok := runCtx.GetArtifact("historical_urls"); ok {
		params, err := readParameters(runCtx.Run.Path(art.Path))
		if err != nil {
			return nil, fmt.Errorf("failed to read historical URLs: %w", err)
		}
		parameters = append(parameters, params...)
	}

	if art, ok := runCtx.GetArtifact("whatweb_raw"); ok {
		var err error
		techs, err = readTechs(runCtx.Run.Path(art.Path))
		if err != nil {
			return nil, fmt.Errorf("failed to read whatweb output: %w", err)
		}
	}

	var techPaths []string
	for _, tech := range techs {
		techPaths = append(techPaths, techEndpoints[tech]...)
	}

	apiPaths = dedupe(apiPaths)
	apiEndpoints = dedupe(apiEndpoints)
	parameters = dedupe(parameters)
	techPaths = dedupe(techPaths)
	sort.Strings(apiPaths)
	sort.Strings(apiEndpoints)
	sort.Strings(parameters)
	sort.Strings(techPaths)

	files := map[string][]string{
		fileAPIPaths:      apiPaths,
		fileAPIEndpoints:  apiEndpoints,
		fileParameters:    parameters,
		fileTechEndpoints: techPaths,
	}

	var manifest []ManifestEntry
	for name, values := range files {
		if len(values) == 0 {
			continue
		}
		if err := writeList(runCtx.Run.Path(outputDir, name), values); err != nil {
			return nil, err
		}
		manifest = append(manifest, ManifestEntry{Name: name, Path: outputDir + "/" + name})
	}
	sort.Slice(manifest, func(i, j int) bool { return manifest[i].Name < manifest[j].Name })

	if err := writeManifest(runCtx.Run.Path(outputDir, fileManifest), manifest); err != nil {
		return nil, err
	}

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, runner.Command{
		Name: "payloadgen (native)",
		Args: []string{
			"-wordlists", fmt.Sprintf("%d", len(manifest)),
			"-api-paths", fmt.Sprintf("%d", len(apiPaths)),
			"-parameters", fmt.Sprintf("%d", len(parameters)),
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	if err := runCtx.AddArtifact("payload_wordlists", modules.Artifact{
		Name: "payload_wordlists",
		Type: "jsonl",
		Path: outputDir + "/" + fileManifest,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish payload wordlists: %w", err)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: "completed",
		OutputFiles: map[string]string{
			"payload_wordlists":      outputDir + "/" + fileManifest,
			"payload_api_paths":      outputDir + "/" + fileAPIPaths,
			"payload_parameters":     outputDir + "/" + fileParameters,
			"payload_tech_endpoints": outputDir + "/" + fileTechEndpoints,
		},
	}, nil
}

// endpointPath returns the path component of an absolute endpoint URL.
func endpointPath(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Path == "" {
		return ""
	}
	path := parsed.Path
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	return path
}

// readJSEndpoints resolves jssecrets endpoint findings to absolute URLs.
func readJSEndpoints(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var endpoints []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		var record struct {
			URL   string `json:"url"`
			Kind  string `json:"kind"`
			Match string `json:"match"`
		}
		if json.Unmarshal(scanner.Bytes(), &record) != nil || record.Kind != "endpoint" {
			continue
		}
		if resolved := resolveEndpoint(record.URL, record.Match); resolved != "" {
			endpoints = append(endpoints, resolved)
		}
	}
	return endpoints, scanner.Err()
}

// readParameters harvests query parameter names from historical URLs (gau).
func readParameters(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var params []string
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parsed, err := url.Parse(line)
		if err != nil {
			continue
		}
		keys := make([]string, 0, len(parsed.Query()))
		for key := range parsed.Query() {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			params = append(params, key)
		}
	}
	return params, scanner.Err()
}

// readTechs extracts technology keywords from whatweb output that have known
// endpoint mappings.
func readTechs(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var techs []string
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		for _, field := range strings.Fields(line) {
			open := strings.IndexByte(field, '[')
			if open <= 0 {
				continue
			}
			tech := strings.ToLower(strings.TrimSpace(field[:open]))
			if _, ok := techEndpoints[tech]; !ok {
				continue
			}
			if _, ok := seen[tech]; ok {
				continue
			}
			seen[tech] = struct{}{}
			techs = append(techs, tech)
		}
	}
	return techs, scanner.Err()
}

func resolveEndpoint(jsURL, endpoint string) string {
	base, err := url.Parse(jsURL)
	if err != nil || base.Hostname() == "" {
		return ""
	}
	ref, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || ref.Path == "" {
		return ""
	}
	if ref.IsAbs() {
		return ref.String()
	}
	if !strings.HasPrefix(endpoint, "/") && !strings.HasPrefix(endpoint, "./") && !strings.HasPrefix(endpoint, "../") {
		return ""
	}
	return base.ResolveReference(ref).String()
}

func dedupe(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func writeList(path string, values []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create payloads directory: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create payload file: %w", err)
	}
	defer func() { _ = file.Close() }()

	writer := bufio.NewWriter(file)
	for _, value := range values {
		if _, err := writer.WriteString(value + "\n"); err != nil {
			return fmt.Errorf("failed to write payload file: %w", err)
		}
	}
	return writer.Flush()
}

func writeManifest(path string, entries []ManifestEntry) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create payloads directory: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create payload manifest: %w", err)
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	for _, entry := range entries {
		if err := encoder.Encode(entry); err != nil {
			return fmt.Errorf("failed to write payload manifest: %w", err)
		}
	}
	return nil
}
