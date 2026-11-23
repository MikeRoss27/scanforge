package vulnintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const nvdPageSize = 2000

type nvdResponse struct {
	TotalResults    int    `json:"totalResults"`
	Version         string `json:"version"`
	Timestamp       string `json:"timestamp"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics map[string][]struct {
		CVSSData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
		BaseSeverity string `json:"baseSeverity"`
	} `json:"metrics"`
	Configurations []struct {
		Nodes []struct {
			CPEMatch []struct {
				Vulnerable            bool   `json:"vulnerable"`
				Criteria              string `json:"criteria"`
				VersionStartIncluding string `json:"versionStartIncluding"`
				VersionStartExcluding string `json:"versionStartExcluding"`
				VersionEndIncluding   string `json:"versionEndIncluding"`
				VersionEndExcluding   string `json:"versionEndExcluding"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
}

// FetchNVD downloads CVEs from the NVD API 2.0, paginated and rate limited
// (6.5s between requests without API key, 0.7s with one, following NVD's
// public limits of 5 / 50 requests per rolling 30s). A non-zero since
// requests only CVEs modified after that time (NVD allows ranges up to 120
// days).
func (c *Client) FetchNVD(ctx context.Context, since time.Time) ([]CVERecord, string, error) {
	base := c.NVDURL
	if base == "" {
		base = DefaultNVDURL
	}
	interval := c.NVDMinInterval
	if interval == 0 {
		interval = 6500 * time.Millisecond
		if c.NVDKey != "" {
			interval = 700 * time.Millisecond
		}
	}
	headers := map[string]string{}
	if c.NVDKey != "" {
		headers["apiKey"] = c.NVDKey
	}
	fetchedAt := c.now()

	var out []CVERecord
	feed := ""
	for start := 0; ; {
		q := url.Values{}
		q.Set("resultsPerPage", fmt.Sprint(nvdPageSize))
		q.Set("startIndex", fmt.Sprint(start))
		if !since.IsZero() {
			q.Set("lastModStartDate", since.UTC().Format("2006-01-02T15:04:05.000"))
			q.Set("lastModEndDate", fetchedAt.Format("2006-01-02T15:04:05.000"))
		}
		sep := "?"
		if strings.Contains(base, "?") {
			sep = "&"
		}
		body, err := c.get(ctx, base+sep+q.Encode(), headers)
		if err != nil {
			return nil, "", fmt.Errorf("nvd: %w", err)
		}
		var page nvdResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, "", fmt.Errorf("nvd: invalid response: %w", err)
		}
		feed = "nvd-api-" + page.Version + "@" + page.Timestamp
		prov := Provenance{Source: SourceNVD, FetchedAt: fetchedAt, FeedVersion: feed}
		for _, v := range page.Vulnerabilities {
			out = append(out, normalizeNVD(v.CVE, prov))
		}
		start += len(page.Vulnerabilities)
		c.progress("nvd: %d/%d", start, page.TotalResults)
		if len(page.Vulnerabilities) == 0 || start >= page.TotalResults {
			break
		}
		if err := c.sleep(ctx, interval); err != nil {
			return nil, "", err
		}
	}
	return out, feed, nil
}

func normalizeNVD(c nvdCVE, prov Provenance) CVERecord {
	rec := CVERecord{ID: c.ID, Published: c.Published, LastModified: c.LastModified, Provenance: prov}
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			rec.Description = d.Value
			break
		}
	}
	for _, key := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
		if ms := c.Metrics[key]; len(ms) > 0 {
			rec.CVSS = ms[0].CVSSData.BaseScore
			sev := ms[0].CVSSData.BaseSeverity
			if sev == "" {
				sev = ms[0].BaseSeverity
			}
			rec.Severity = strings.ToLower(sev)
			break
		}
	}
	for _, cfg := range c.Configurations {
		for _, node := range cfg.Nodes {
			for _, m := range node.CPEMatch {
				if !m.Vulnerable {
					continue
				}
				cpe, ok := ParseCPE(m.Criteria)
				if !ok {
					continue
				}
				rec.Matches = append(rec.Matches, CPEMatch{
					Criteria: m.Criteria, Vendor: cpe.Vendor, Product: cpe.Product, Version: cpe.Version,
					StartIncl: m.VersionStartIncluding, StartExcl: m.VersionStartExcluding,
					EndIncl: m.VersionEndIncluding, EndExcl: m.VersionEndExcluding,
				})
			}
		}
	}
	return rec
}

// MergeCVEs overlays updated records onto existing ones by CVE ID.
func MergeCVEs(existing, updated []CVERecord) []CVERecord {
	idx := make(map[string]int, len(existing))
	out := append([]CVERecord(nil), existing...)
	for i, r := range out {
		idx[r.ID] = i
	}
	for _, r := range updated {
		if i, ok := idx[r.ID]; ok {
			out[i] = r
		} else {
			idx[r.ID] = len(out)
			out = append(out, r)
		}
	}
	return out
}
