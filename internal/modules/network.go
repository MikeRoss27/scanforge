package modules

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ProxyArgs returns the flag/value pair to append to a command's args when a
// proxy is configured, or nil otherwise. flag is the tool-specific proxy
// option (e.g. "-proxy", "-x", "--proxy").
func (c *RunContext) ProxyArgs(flag string) []string {
	if c.Proxy == "" {
		return nil
	}
	return []string{flag, c.Proxy}
}

// ProxyHost returns the configured proxy without its scheme, for tools that
// expect a bare host[:port] rather than a URL (e.g. whatweb's --proxy).
func (c *RunContext) ProxyHost() string {
	value := c.Proxy
	for _, prefix := range []string{"http://", "https://", "socks5://", "socks5h://", "socks4://"} {
		if strings.HasPrefix(value, prefix) {
			return strings.TrimPrefix(value, prefix)
		}
	}
	return value
}

// HeaderArgs returns repeated flag/value pairs, one per configured header,
// suitable for tools that accept custom headers as repeatable CLI flags
// (e.g. "-H" "Authorization: Bearer ...").
func (c *RunContext) HeaderArgs(flag string) []string {
	if len(c.Headers) == 0 {
		return nil
	}
	args := make([]string, 0, len(c.Headers)*2)
	for _, header := range c.Headers {
		args = append(args, flag, header)
	}
	return args
}

// ApplyHeaders sets the configured "Name: Value" headers on an outgoing HTTP
// request, matching what the native HTTP modules do individually.
func ApplyHeaders(req *http.Request, headers []string) {
	for _, header := range headers {
		name, value, ok := strings.Cut(header, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || name == "" {
			continue
		}
		req.Header.Set(name, value)
	}
}

// NewProxyClient builds an HTTP client that honors the configured proxy. It
// returns the client and a close function for the transport's idle
// connections.
func NewProxyClient(proxy string, timeout time.Duration) (*http.Client, func(), error) {
	transport := &http.Transport{}
	if proxy != "" {
		parsed, err := url.Parse(proxy)
		if err != nil {
			return nil, func() {}, fmt.Errorf("failed to parse proxy %q: %w", proxy, err)
		}
		transport.Proxy = http.ProxyURL(parsed)
	}
	return &http.Client{Timeout: timeout, Transport: transport}, transport.CloseIdleConnections, nil
}

// NoRedirectCheckRedirect tells an HTTP client to not follow redirects; the
// WP modules use it when the redirect itself is the signal (e.g. ?author=
// redirects for user enumeration) or for auth probes where following a
// redirect would mask a login failure.
func NoRedirectCheckRedirect(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

// ReadAliveHosts normalizes the scoped alive_urls artifact to a deduplicated
// list of scheme://host[:port] bases. Caller is responsible for having
// produced/scoped the artifact.
func ReadAliveHosts(path string, maxHosts int) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = file.Close() }()

	seen := make(map[string]struct{})
	bases := []string{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		base, ok := WPBaseURL(strings.TrimSpace(scanner.Text()))
		if !ok {
			continue
		}
		if _, dup := seen[base]; dup {
			continue
		}
		seen[base] = struct{}{}
		bases = append(bases, base)
		if maxHosts > 0 && len(bases) >= maxHosts {
			return bases, scanner.Err()
		}
	}
	return bases, scanner.Err()
}

// WPBaseURL normalizes a raw alive URL (possibly with path/query) down to
// scheme://host[:port]. Non-HTTP(S) or scheme-relative inputs are rejected.
func WPBaseURL(raw string) (string, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return "", false
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	return scheme + "://" + parsed.Host, true
}

// WPBody fetches a URL body with a hard cap, applying the configured headers.
// It honors ctx for cancellation. The caller is expected to channel the
// returned status/body/error; transport errors are swallowed as "not found"
// signals so a flaky host does not fail the whole module.
func WPBody(ctx context.Context, client *http.Client, target string, headers []string, maxBody int64) (int, []byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	ApplyHeaders(req, headers)
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return resp.StatusCode, nil, resp.Header, err
	}
	return resp.StatusCode, body, resp.Header, nil
}
