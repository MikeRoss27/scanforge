package vulnintel

import (
	"context"
	"encoding/json"
	"fmt"
)

type kevFeed struct {
	CatalogVersion  string `json:"catalogVersion"`
	DateReleased    string `json:"dateReleased"`
	Vulnerabilities []struct {
		CVEID      string `json:"cveID"`
		Vendor     string `json:"vendorProject"`
		Product    string `json:"product"`
		Name       string `json:"vulnerabilityName"`
		DateAdded  string `json:"dateAdded"`
		DueDate    string `json:"dueDate"`
		Ransomware string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

// FetchKEV downloads the CISA Known Exploited Vulnerabilities JSON feed.
func (c *Client) FetchKEV(ctx context.Context) ([]KEVRecord, string, error) {
	u := c.KEVURL
	if u == "" {
		u = DefaultKEVURL
	}
	body, err := c.get(ctx, u, nil)
	if err != nil {
		return nil, "", fmt.Errorf("kev: %w", err)
	}
	var feed kevFeed
	if err := json.Unmarshal(body, &feed); err != nil {
		return nil, "", fmt.Errorf("kev: invalid feed: %w", err)
	}
	version := feed.CatalogVersion
	if feed.DateReleased != "" {
		version += "@" + feed.DateReleased
	}
	prov := Provenance{Source: SourceKEV, FetchedAt: c.now(), FeedVersion: version}
	out := make([]KEVRecord, 0, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		out = append(out, KEVRecord{CVEID: v.CVEID, Vendor: v.Vendor, Product: v.Product, Name: v.Name,
			DateAdded: v.DateAdded, DueDate: v.DueDate, Ransomware: v.Ransomware, Provenance: prov})
	}
	return out, version, nil
}
