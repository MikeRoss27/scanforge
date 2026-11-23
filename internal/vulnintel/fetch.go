package vulnintel

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// HTTPDoer is the injectable transport; *http.Client satisfies it.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Default upstream endpoints.
const (
	DefaultNVDURL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	DefaultKEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultEPSSURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
)

// NVDKeyFromEnv returns the optional NVD API key. Never log the result.
func NVDKeyFromEnv(getenv func(string) string) string {
	for _, name := range []string{"SCANFORGE_NVD_API_KEY", "NVD_API_KEY"} {
		if v := getenv(name); v != "" {
			return v
		}
	}
	return ""
}

// Client fetches feeds. It is only used by explicit updates.
type Client struct {
	HTTP     HTTPDoer
	NVDURL   string
	KEVURL   string
	EPSSURL  string
	NVDKey   string // optional; sent as a header, never logged
	Now      func() time.Time
	Sleep    func(context.Context, time.Duration) error
	Progress func(format string, args ...any)
	// NVDMinInterval overrides the spacing between NVD requests.
	NVDMinInterval time.Duration
	// MaxRetries for 403/429/5xx responses (default 3).
	MaxRetries int
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

func (c *Client) progress(format string, args ...any) {
	if c.Progress != nil {
		c.Progress(format, args...)
	}
}

func (c *Client) sleep(ctx context.Context, d time.Duration) error {
	if c.Sleep != nil {
		return c.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (c *Client) doer() HTTPDoer {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 5 * time.Minute}
}

// get performs one GET with retry on throttling. Headers (which may carry the
// API key) are never included in errors or progress output.
func (c *Client) get(ctx context.Context, url string, headers map[string]string) ([]byte, error) {
	retries := c.MaxRetries
	if retries == 0 {
		retries = 3
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "scanforge-vulnintel")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := c.doer().Do(req)
		if err != nil {
			return nil, fmt.Errorf("request failed: %w", err)
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusOK:
			if readErr != nil {
				return nil, fmt.Errorf("failed to read response: %w", readErr)
			}
			return body, nil
		case (resp.StatusCode == 403 || resp.StatusCode == 429 || resp.StatusCode >= 500) && attempt < retries:
			wait := time.Duration(attempt+1) * 10 * time.Second
			if secs, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && secs >= 0 {
				wait = time.Duration(secs) * time.Second
			}
			c.progress("HTTP %d, retrying in %s", resp.StatusCode, wait)
			if err := c.sleep(ctx, wait); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
		}
	}
}
