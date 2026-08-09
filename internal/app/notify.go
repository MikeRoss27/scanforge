package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/report"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

// webhookPayload is the generic JSON document posted at the end of a run.
// "text" is the field every major webhook receiver (Slack, Discord, Teams)
// renders, so the same payload works everywhere.
type webhookPayload struct {
	Text       string         `json:"text"`
	Target     string         `json:"target"`
	Profile    string         `json:"profile"`
	Status     string         `json:"status"`
	Assets     int            `json:"assets"`
	Ports      int            `json:"ports"`
	Vulns      int            `json:"vulnerabilities"`
	Severities map[string]int `json:"severity_counts"`
	RunDir     string         `json:"run_dir"`
}

// notifyWebhook posts the run summary to the configured webhook URL. The
// notification is best-effort: failures are logged, never fatal for the run.
func notifyWebhook(ctx context.Context, cfg *config.Config, scanRun *storage.Run, rep *report.Report) error {
	if cfg.Webhook.URL == "" {
		return nil
	}

	payload := buildWebhookPayload(scanRun, rep)
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, cfg.Webhook.URL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "scanforge")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}

func buildWebhookPayload(scanRun *storage.Run, rep *report.Report) webhookPayload {
	ports := 0
	severities := make(map[string]int)
	for _, asset := range rep.Assets {
		ports += len(asset.Ports)
		for _, vuln := range asset.Vulnerabilities {
			severities[vuln.Severity]++
		}
	}
	vulns := 0
	for _, count := range severities {
		vulns += count
	}

	var order []string
	for sev := range severities {
		order = append(order, sev)
	}
	sort.Strings(order)

	text := fmt.Sprintf("ScanForge: target=%s profile=%s status=%s assets=%d ports=%d vulnerabilities=%d",
		scanRun.Target, scanRun.Manifest.Profile, scanRun.Manifest.Status,
		len(rep.Assets), ports, vulns)
	if len(order) > 0 {
		detail := ""
		for _, sev := range order {
			detail += fmt.Sprintf(" %s=%d", sev, severities[sev])
		}
		text += " (" + detail[1:] + ")"
	}

	return webhookPayload{
		Text:       text,
		Target:     scanRun.Target,
		Profile:    scanRun.Manifest.Profile,
		Status:     scanRun.Manifest.Status,
		Assets:     len(rep.Assets),
		Ports:      ports,
		Vulns:      vulns,
		Severities: severities,
		RunDir:     scanRun.RootDir,
	}
}
