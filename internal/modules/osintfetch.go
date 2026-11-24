package modules

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

// FetchResult is the outcome of one capped HTTP GET performed by an OSINT
// module (crt.sh, RDAP). Truncated reports that the body exceeded the size
// cap and was cut, so callers must not trust it as complete JSON.
type FetchResult struct {
	Status    int
	Body      []byte
	Truncated bool
	// RetryAfter is the server-requested delay of a 429/503 answer, if any.
	RetryAfter time.Duration
}

// Fetcher is the injectable HTTP boundary of the native passive OSINT modules
// (ctlogs, asnmap). Production code uses NewOSINTFetcher; tests substitute an
// httptest-backed or fake implementation so no real network is ever touched.
type Fetcher interface {
	Get(ctx context.Context, rawURL string) (*FetchResult, error)
}

type osintFetcher struct {
	client   *http.Client
	maxBytes int64
	ua       string
}

// NewOSINTFetcher builds a Fetcher with a per-request timeout, a hard body
// size cap and optional proxy support. Operator-supplied --header values are
// deliberately NOT applied: they carry credentials for the scan target and
// must never be sent to third-party public services.
func NewOSINTFetcher(proxy string, timeout time.Duration, maxBytes int64) (Fetcher, func(), error) {
	client, closeConn, err := NewProxyClient(proxy, timeout)
	if err != nil {
		return nil, func() {}, err
	}
	return &osintFetcher{client: client, maxBytes: maxBytes, ua: "scanforge-osint/1.0"}, closeConn, nil
}

func (f *osintFetcher) Get(ctx context.Context, rawURL string) (*FetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", f.ua)
	req.Header.Set("Accept", "application/json, application/rdap+json")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.maxBytes+1))
	if err != nil {
		return nil, err
	}
	res := &FetchResult{Status: resp.StatusCode, Body: body}
	if int64(len(body)) > f.maxBytes {
		res.Body = body[:f.maxBytes]
		res.Truncated = true
	}
	if secs, perr := strconv.Atoi(resp.Header.Get("Retry-After")); perr == nil && secs > 0 {
		res.RetryAfter = time.Duration(secs) * time.Second
	}
	return res, nil
}

// RetryPolicy bounds FetchWithRetry. Transport errors, HTTP 429 and 5xx are
// retried with exponential backoff and jitter; everything else is returned
// to the caller on the first attempt.
type RetryPolicy struct {
	Attempts  int
	BaseDelay time.Duration
	MaxDelay  time.Duration
}

// DefaultRetryPolicy suits public, occasionally overloaded services.
var DefaultRetryPolicy = RetryPolicy{Attempts: 4, BaseDelay: 2 * time.Second, MaxDelay: 30 * time.Second}

func retryable(status int) bool { return status == http.StatusTooManyRequests || status >= 500 }

// FetchWithRetry performs GET through f, retrying per policy. It returns the
// last result (possibly a non-2xx one) when the server kept answering, or the
// last error when it never did. Cancellation is honored between attempts.
func FetchWithRetry(ctx context.Context, f Fetcher, rawURL string, policy RetryPolicy) (*FetchResult, error) {
	attempts := policy.Attempts
	if attempts < 1 {
		attempts = 1
	}
	var (
		lastRes *FetchResult
		lastErr error
	)
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			delay := policy.BaseDelay << (attempt - 1)
			if lastRes != nil && lastRes.RetryAfter > delay {
				delay = lastRes.RetryAfter
			}
			if policy.MaxDelay > 0 && delay > policy.MaxDelay {
				delay = policy.MaxDelay
			}
			if delay > 0 {
				delay += time.Duration(rand.Int63n(int64(delay)/4 + 1))
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
		res, err := f.Get(ctx, rawURL)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastRes, lastErr = nil, err
			continue
		}
		if !retryable(res.Status) {
			return res, nil
		}
		lastRes, lastErr = res, nil
	}
	if lastRes != nil {
		return lastRes, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no attempt made")
	}
	return nil, fmt.Errorf("after %d attempts: %w", attempts, lastErr)
}
