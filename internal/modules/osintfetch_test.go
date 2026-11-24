package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var testRetry = RetryPolicy{Attempts: 3, BaseDelay: time.Millisecond, MaxDelay: 3 * time.Millisecond}

func TestFetchWithRetryRecoversFromServerErrors(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch hits.Add(1) {
		case 1:
			w.WriteHeader(http.StatusTooManyRequests)
		case 2:
			w.WriteHeader(http.StatusBadGateway)
		default:
			_, _ = w.Write([]byte(`ok`))
		}
	}))
	defer srv.Close()
	f, closeConn, err := NewOSINTFetcher("", 5*time.Second, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer closeConn()
	res, err := FetchWithRetry(context.Background(), f, srv.URL, testRetry)
	if err != nil || res.Status != 200 || string(res.Body) != "ok" || hits.Load() != 3 {
		t.Fatalf("res=%+v err=%v hits=%d", res, err, hits.Load())
	}
}

func TestFetchWithRetryDoesNotRetryClientErrors(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	f, closeConn, _ := NewOSINTFetcher("", 5*time.Second, 1024)
	defer closeConn()
	res, err := FetchWithRetry(context.Background(), f, srv.URL, testRetry)
	if err != nil || res.Status != 404 || hits.Load() != 1 {
		t.Fatalf("res=%+v err=%v hits=%d", res, err, hits.Load())
	}
}

func TestFetchWithRetryTransportErrorAndCancel(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // connection refused
	f, closeConn, _ := NewOSINTFetcher("", time.Second, 1024)
	defer closeConn()
	if _, err := FetchWithRetry(context.Background(), f, url, testRetry); err == nil || !strings.Contains(err.Error(), "3 attempts") {
		t.Fatalf("err = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := FetchWithRetry(ctx, f, url, testRetry); err == nil {
		t.Fatal("expected cancellation error")
	}
}

func TestOSINTFetcherCapsBodyAndIgnoresOperatorHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || !strings.HasPrefix(r.Header.Get("User-Agent"), "scanforge") {
			t.Errorf("unexpected headers: %v", r.Header)
		}
		_, _ = w.Write([]byte(strings.Repeat("x", 100)))
	}))
	defer srv.Close()
	f, closeConn, _ := NewOSINTFetcher("", 5*time.Second, 10)
	defer closeConn()
	res, err := f.Get(context.Background(), srv.URL)
	if err != nil || !res.Truncated || len(res.Body) != 10 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}
