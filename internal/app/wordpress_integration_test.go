package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/modules/wpcve"
	"github.com/MikeRoss27/scanforge/internal/modules/wpdetect"
	"github.com/MikeRoss27/scanforge/internal/modules/wpexposure"
	"github.com/MikeRoss27/scanforge/internal/modules/wpplugins"
	"github.com/MikeRoss27/scanforge/internal/modules/wpthemes"
	"github.com/MikeRoss27/scanforge/internal/modules/wpusers"
	"github.com/MikeRoss27/scanforge/internal/modules/wpxmlrpc"
	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	"github.com/MikeRoss27/scanforge/internal/runner"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

const wpHome = `<html><head><meta name="generator" content="WordPress 6.4.2" /></head>
<body><link rel="stylesheet" href="/wp-content/themes/astra/style.css?ver=3.6.3" />
<script src="/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.3.1"></script>
</body></html>`

const wpFeed = `<?xml version="1.0"?><rss><channel><generator>https://wordpress.org/?v=6.4.2</generator></channel></rss>`

const wpReadme = `<html><head><title>WordPress</title></head><body><h1>ABOUT WORDPRESS</h1><p>Version 6.4.2</p></body></html>`

const wpJSON = `{"name":"Fake WP","namespaces":["oembed/1.0","wp/v2"]}`

const wpUsersJSON = `[{"id":3,"name":"Site Admin","slug":"site-admin"}]`

const wpListMethods = `<?xml version="1.0"?>
<methodResponse><params><param><value><array><data>
<member><value><string>system.multicall</string></value></member>
<member><value><string>system.listMethods</string></value></member>
<member><value><string>pingback.ping</string></value></member>
<member><value><string>wp.getUsersBlogs</string></value></member>
</data></array></value></param></params></methodResponse>`

const pluginReadmeCF7 = `=== Contact Form 7 ===
Stable tag: 5.3.1
Requires at least: 6.0
`

const themeStyleAstra = `/*
Theme Name: Astra
Version: 3.6.3
*/`

const debugLog = `[18-Nov-2026 10:00:00 UTC] PHP Fatal error:  Uncaught Error in /var/www/html/wp-content/themes/x/functions.php on line 42
`

const configBackup = `<?php
define('DB_NAME', 'wordpress');
define('DB_PASSWORD', 'super-secret-password');
`

// staticAlive publishes the httptest URL as the scoped alive_urls artifact so
// the WP chain has an input without any external tool.
type staticAlive struct{ url string }

func (staticAlive) Name() string        { return "fixture-alive" }
func (staticAlive) Description() string { return "test fixture publishing alive_urls" }
func (staticAlive) Requires() []string  { return nil }
func (staticAlive) Produces() []string  { return []string{"alive_urls"} }
func (s staticAlive) Run(_ context.Context, runCtx *modules.RunContext, _ runner.Executor) (*modules.Result, error) {
	rel := "02_http/alive_urls.txt"
	path := runCtx.Run.Path(rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(s.url+"\n"), 0o644); err != nil {
		return nil, err
	}
	if err := runCtx.AddArtifact("alive_urls", modules.Artifact{Name: "alive_urls", Type: "text", Path: rel}); err != nil {
		return nil, err
	}
	return &modules.Result{Name: s.Name(), Status: "completed", OutputFiles: map[string]string{"alive_urls": rel}}, nil
}

func TestWordPressChainEndToEnd(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.RawQuery {
		case "feed=rss2":
			io.WriteString(w, wpFeed)
		case "author=1":
			w.Header().Set("Location", "/author/site-admin/")
			w.WriteHeader(http.StatusMovedPermanently)
		default:
			io.WriteString(w, wpHome)
		}
	})
	mux.HandleFunc("/readme.html", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, wpReadme) })
	mux.HandleFunc("/wp-json/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, wpJSON)
	})
	mux.HandleFunc("/wp-json/wp/v2/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, wpUsersJSON)
	})
	mux.HandleFunc("/xmlrpc.php", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		io.WriteString(w, wpListMethods)
	})
	mux.HandleFunc("/wp-content/plugins/contact-form-7/readme.txt", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, pluginReadmeCF7) })
	mux.HandleFunc("/wp-content/themes/astra/style.css", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, themeStyleAstra) })
	mux.HandleFunc("/wp-content/debug.log", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, debugLog) })
	mux.HandleFunc("/wp-config.php.bak", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, configBackup) })
	server := httptest.NewServer(mux)
	defer server.Close()

	slugs := filepath.Join(t.TempDir(), "slugs.txt")
	if err := os.WriteFile(slugs, []byte("contact-form-7\ndefinitely-not-a-real-slug-xyz\nastra\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.DefaultScope = ""
	// Override the wp chain to stay entirely local and self-contained.
	cfg.Profiles["wp"] = []string{
		"fixture-alive",
		"wpdetect",
		"wpplugins",
		"wpthemes",
		"wpusers",
		"wpexposure",
		"wpxmlrpc",
		"wpcve",
	}

	run, err := storage.NewRunStore(t.TempDir()).Create("example.test")
	if err != nil {
		t.Fatal(err)
	}

	registry := modules.NewRegistry()
	registry.Register(staticAlive{server.URL})
	registry.Register(wpdetect.New())
	registry.Register(wpplugins.New())
	registry.Register(wpthemes.New())
	registry.Register(wpusers.New())
	registry.Register(wpexposure.New())
	registry.Register(wpxmlrpc.New())
	registry.Register(wpcve.New())

	results, err := orchestrator.New(runner.NewDryRunExecutor(false), registry).Run(
		context.Background(), run, orchestrator.Options{
			Target:    server.URL,
			Profile:   "wp",
			Config:    cfg,
			WordPress: modules.WordPressOptions{DetectionMode: "aggressive", Wordlist: slugs},
		}, nil)
	if err != nil {
		t.Fatalf("orchestrator run failed: %v", err)
	}
	for _, result := range results {
		if result.Status != "completed" {
			t.Fatalf("%s status = %q (err artifact may be logged)", result.Name, result.Status)
		}
	}

	fingerprint := readJSONLines(t, run.Path("04_wordpress", "wp-fingerprint.jsonl"))
	if len(fingerprint) != 1 {
		t.Fatalf("expected 1 fingerprint record, got %d", len(fingerprint))
	}
	if fingerprint[0]["core_version"] != "6.4.2" || fingerprint[0]["is_wordpress"] != true {
		t.Fatalf("fingerprint = %v, want is_wordpress=true core_version=6.4.2", fingerprint[0])
	}

	plugins := readJSONLines(t, run.Path("04_wordpress", "wp-plugins.jsonl"))
	byPlugin := map[string]map[string]any{}
	for _, item := range plugins {
		byPlugin[item["plugin"].(string)] = item
	}
	cf7, ok := byPlugin["contact-form-7"]
	if !ok {
		t.Fatalf("contact-form-7 not detected, plugins = %v", byPlugin)
	}
	if cf7["version"] != "5.3.1" {
		t.Fatalf("contact-form-7 version = %v, want 5.3.1", cf7["version"])
	}

	themes := readJSONLines(t, run.Path("04_wordpress", "wp-themes.jsonl"))
	byTheme := map[string]map[string]any{}
	for _, item := range themes {
		byTheme[item["theme"].(string)] = item
	}
	astra, ok := byTheme["astra"]
	if !ok {
		t.Fatalf("astra not detected, themes = %v", byTheme)
	}
	if astra["version"] != "3.6.3" {
		t.Fatalf("astra version = %v, want 3.6.3", astra["version"])
	}

	users := readJSONLines(t, run.Path("04_wordpress", "wp-users.jsonl"))
	logins := map[string]bool{}
	for _, item := range users {
		logins[item["login"].(string)] = true
	}
	if !logins["site-admin"] {
		t.Fatalf("expected enumerated user site-admin, got %v", logins)
	}

	exposures := readJSONLines(t, run.Path("04_wordpress", "wp-exposure.jsonl"))
	checks := map[string]bool{}
	for _, item := range exposures {
		checks[item["check"].(string)] = true
	}
	for _, want := range []string{"wp-config-backup", "debug-log"} {
		if !checks[want] {
			t.Fatalf("expected exposure check %q, got %v", want, checks)
		}
	}

	xmlrpc := readJSONLines(t, run.Path("04_wordpress", "wp-xmlrpc.jsonl"))
	if len(xmlrpc) != 1 {
		t.Fatalf("expected 1 xmlrpc record, got %d", len(xmlrpc))
	}
	if xmlrpc[0]["enabled"] != true || xmlrpc[0]["has_multicall"] != true {
		t.Fatalf("xmlrpc = %v, want enabled + multicall", xmlrpc[0])
	}

	cveFindings := readJSONLines(t, run.Path("06_vulns", "wp-cve-findings.jsonl"))
	cves := map[string]bool{}
	for _, item := range cveFindings {
		cves[item["cve_id"].(string)] = true
	}
	if !cves["CVE-2020-35489"] {
		t.Fatalf("expected CVE-2020-35489 (contact-form-7 5.3.1), got %v", cves)
	}
}

func readJSONLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var items []map[string]any
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var item map[string]any
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			t.Fatalf("invalid JSONL in %s: %v\nline: %s", path, err, line)
		}
		items = append(items, item)
	}
	return items
}
