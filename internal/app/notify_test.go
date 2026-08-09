package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/report"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

func TestBuildWebhookPayload(t *testing.T) {
	run := &storage.Run{
		Target:  "example.com",
		RootDir: "/tmp/runs/example.com/2026-08-09",
		Manifest: storage.RunManifest{
			Target:  "example.com",
			Profile: "web",
			Status:  "completed",
		},
	}
	rep := report.NewReport("example.com", "web")
	asset := rep.GetOrCreateAsset("a.example.com")
	asset.Ports = map[int]*report.Port{80: {Number: 80}}
	asset.Vulnerabilities = append(asset.Vulnerabilities,
		&report.Vulnerability{Severity: "critical", TemplateID: "c1", Title: "A", MatchedAt: "a.example.com"},
		&report.Vulnerability{Severity: "critical", TemplateID: "c2", Title: "B", MatchedAt: "a.example.com"},
		&report.Vulnerability{Severity: "low", TemplateID: "l1", Title: "C", MatchedAt: "a.example.com"})

	payload := buildWebhookPayload(run, rep)
	if payload.Target != "example.com" || payload.Status != "completed" {
		t.Fatalf("payload = %+v", payload)
	}
	if payload.Assets != 1 || payload.Ports != 1 || payload.Vulns != 3 {
		t.Fatalf("counts = %d/%d/%d", payload.Assets, payload.Ports, payload.Vulns)
	}
	if payload.Severities["critical"] != 2 || payload.Severities["low"] != 1 {
		t.Fatalf("severity counts = %v", payload.Severities)
	}
	for _, part := range []string{"target=example.com", "profile=web", "critical=2"} {
		if !strings.Contains(payload.Text, part) {
			t.Fatalf("text = %q misses %q", payload.Text, part)
		}
	}
}

func TestNotifyWebhookPostsPayload(t *testing.T) {
	received := make(chan webhookPayload, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Fatalf("content-type = %q", ct)
		}
		var payload webhookPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		received <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	run := &storage.Run{
		Target:  "example.com",
		RootDir: filepath.Join(t.TempDir(), "run"),
		Manifest: storage.RunManifest{
			Target:  "example.com",
			Profile: "safe",
			Status:  "partial",
		},
	}
	rep := report.NewReport("example.com", "safe")

	cfg := &config.Config{Webhook: config.Webhook{URL: server.URL}}
	if err := notifyWebhook(context.Background(), cfg, run, rep); err != nil {
		t.Fatalf("notifyWebhook() error = %v", err)
	}

	select {
	case payload := <-received:
		if payload.Target != "example.com" || payload.Status != "partial" {
			t.Fatalf("payload = %+v", payload)
		}
	default:
		t.Fatal("no webhook payload received")
	}
}

func TestNotifyWebhookNoopWithoutURL(t *testing.T) {
	run := &storage.Run{}
	rep := report.NewReport("example.com", "safe")
	if err := notifyWebhook(context.Background(), &config.Config{}, run, rep); err != nil {
		t.Fatalf("noop notifyWebhook() error = %v", err)
	}
}

func TestNotifyWebhookReportsServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := &config.Config{Webhook: config.Webhook{URL: server.URL}}
	run := &storage.Run{Manifest: storage.RunManifest{Target: "example.com"}}
	err := notifyWebhook(context.Background(), cfg, run, report.NewReport("example.com", "safe"))
	if err == nil {
		t.Fatal("server error must be surfaced")
	}
}
