package payloadgen

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/url"
	"os"
	"sort"
	"strings"
)

// EndpointReader abstracts endpoint extraction for testing.
type EndpointReader interface {
	ReadEndpoints(ctx context.Context, r io.Reader) ([]string, error)
}

// ParameterReader abstracts parameter extraction for testing.
type ParameterReader interface {
	ReadParameters(ctx context.Context, r io.Reader) ([]string, error)
}

// TechReader abstracts tech extraction for testing.
type TechReader interface {
	ReadTechs(ctx context.Context, r io.Reader) ([]string, error)
}

// Limits and blocklists.
const (
	defaultMaxItems = 2_000_000 // guard against 10M-line historical_urls
	scanBuffer      = 64 * 1024
	maxScanToken    = 1024 * 1024
)

// trackingParamsBlocklist filters noisy marketing/analytics params from wordlists.
var trackingParamsBlocklist = map[string]struct{}{
	"utm_source": {}, "utm_medium": {}, "utm_campaign": {}, "utm_term": {}, "utm_content": {},
	"utm_id": {}, "utm_name": {}, "gclid": {}, "fbclid": {}, "msclkid": {},
	"igshid": {}, "mc_eid": {}, "mc_cid": {}, "_ga": {}, "_gid": {},
	"yclid": {}, "dclid": {}, "zanpid": {}, "aff_id": {}, "aff_sub": {},
	"ref": {}, "referrer": {}, "referer": {},
}

// readStats is internal telemetry surfaced via slog and optionally manifest.
type readStats struct {
	Lines    int `json:"lines"`
	Kept     int `json:"kept"`
	Ignored  int `json:"ignored"`
	Rejected int `json:"rejected"` // scope or blocklist
}

// readJSEndpointsFromReader resolves jssecrets endpoint findings to absolute URLs.
// It is the testable core: caller provides an io.Reader (file in prod, buffer in tests).
func readJSEndpointsFromReader(ctx context.Context, r io.Reader) ([]string, error) {
	var endpoints []string
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, scanBuffer), maxScanToken)
	stats := readStats{}
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return endpoints, ctx.Err()
		default:
		}
		stats.Lines++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var record struct {
			URL   string `json:"url"`
			Kind  string `json:"kind"`
			Match string `json:"match"`
		}
		if err := json.Unmarshal(line, &record); err != nil {
			stats.Ignored++
			slog.Warn("payloadgen: ignoring malformed js_secrets line", "error", err.Error())
			continue
		}
		if record.Kind != "endpoint" {
			stats.Ignored++
			continue
		}
		if len(endpoints) >= defaultMaxItems {
			slog.Warn("payloadgen: js_secrets maxItems reached, truncating", "max", defaultMaxItems)
			break
		}
		if resolved := resolveEndpoint(record.URL, record.Match); resolved != "" {
			endpoints = append(endpoints, resolved)
			stats.Kept++
		} else {
			stats.Ignored++
			slog.Debug("payloadgen: could not resolve endpoint", "js_url", record.URL, "match", record.Match)
		}
	}
	if err := scanner.Err(); err != nil {
		return endpoints, err
	}
	slog.Debug("payloadgen: read js endpoints", "lines", stats.Lines, "kept", stats.Kept, "ignored", stats.Ignored)
	return endpoints, nil
}

// readParametersFromReader harvests query parameter names from historical URLs (gau).
func readParametersFromReader(ctx context.Context, r io.Reader) ([]string, error) {
	var params []string
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, scanBuffer), maxScanToken)
	stats := readStats{}
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return params, ctx.Err()
		default:
		}
		stats.Lines++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if len(params) >= defaultMaxItems {
			slog.Warn("payloadgen: historical_urls maxItems reached, truncating", "max", defaultMaxItems)
			break
		}
		parsed, err := url.Parse(line)
		if err != nil {
			stats.Ignored++
			slog.Debug("payloadgen: ignoring unparsable url", "line", line, "error", err.Error())
			continue
		}
		// Use Query() to handle decoding, but preserve original keys.
		query := parsed.Query()
		if len(query) == 0 {
			continue
		}
		keys := make([]string, 0, len(query))
		for key := range query {
			// Filter tracking params (case-insensitive)
			lower := strings.ToLower(key)
			if _, blocked := trackingParamsBlocklist[lower]; blocked {
				stats.Rejected++
				continue
			}
			// Optional: normalize to lower? Keep original but dedupe case-insensitively by lowering for seen.
			// We keep the first casing encountered to preserve server-expected case while avoiding duplicates like ID/id.
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			// Dedupe case-insensitively: "ID" and "id" count as same param for fuzzing.
			lower := strings.ToLower(key)
			if _, ok := seen[lower]; ok {
				continue
			}
			seen[lower] = struct{}{}
			params = append(params, key)
			stats.Kept++
		}
	}
	if err := scanner.Err(); err != nil {
		return params, err
	}
	slog.Debug("payloadgen: read parameters", "lines", stats.Lines, "kept", stats.Kept, "ignored", stats.Ignored, "rejected", stats.Rejected)
	return params, nil
}

// readTechsFromReader extracts technology keywords from whatweb output that have known endpoint mappings.
// registry is injected so tests can provide a deterministic map; production passes getTechRegistry().
func readTechsFromReader(ctx context.Context, r io.Reader, registry map[string][]string) ([]string, error) {
	if registry == nil {
		registry = defaultTechEndpoints
	}
	var techs []string
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, scanBuffer), maxScanToken)
	stats := readStats{}
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return techs, ctx.Err()
		default:
		}
		stats.Lines++
		line := scanner.Text()
		// whatweb lines are space-separated fields; each field may be "Tech[version]" or "Tech/version"
		for _, field := range strings.Fields(line) {
			token := normalizeTechToken(field)
			if token == "" {
				continue
			}
			if _, ok := registry[token]; !ok {
				// Also try lookup via helper (handles next.js vs nextjs)
				if len(lookupTechEndpoints(registry, token)) == 0 {
					continue
				}
			}
			if _, ok := seen[token]; ok {
				continue
			}
			if len(techs) >= defaultMaxItems {
				slog.Warn("payloadgen: whatweb maxItems reached, truncating", "max", defaultMaxItems)
				break
			}
			seen[token] = struct{}{}
			techs = append(techs, token)
			stats.Kept++
		}
	}
	if err := scanner.Err(); err != nil {
		return techs, err
	}
	slog.Debug("payloadgen: read techs", "lines", stats.Lines, "kept", stats.Kept)
	return techs, nil
}

// Wrappers that open files — keep backward-compatible signatures for existing tests and callers.
// They delegate to the io.Reader cores above.

//nolint:unused // kept for backward compatibility
func readJSEndpoints(path string) ([]string, error) {
	return readJSEndpointsWithContext(context.Background(), path)
}

func readJSEndpointsWithContext(ctx context.Context, path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return readJSEndpointsFromReader(ctx, file)
}

func readParameters(path string) ([]string, error) {
	return readParametersWithContext(context.Background(), path)
}

func readParametersWithContext(ctx context.Context, path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return readParametersFromReader(ctx, file)
}

//nolint:unused // kept for backward compatibility
func readTechs(path string) ([]string, error) {
	return readTechsWithContext(context.Background(), path)
}

func readTechsWithContext(ctx context.Context, path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return readTechsFromReader(ctx, file, getTechRegistry())
}
