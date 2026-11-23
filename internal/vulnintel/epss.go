package vulnintel

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// FetchEPSS downloads the FIRST EPSS daily CSV (plain or gzip).
func (c *Client) FetchEPSS(ctx context.Context) ([]EPSSRecord, string, error) {
	u := c.EPSSURL
	if u == "" {
		u = DefaultEPSSURL
	}
	body, err := c.get(ctx, u, nil)
	if err != nil {
		return nil, "", fmt.Errorf("epss: %w", err)
	}
	recs, version, err := ParseEPSS(body, c.now())
	if err != nil {
		return nil, "", fmt.Errorf("epss: %w", err)
	}
	return recs, version, nil
}

// ParseEPSS parses the EPSS CSV: an optional "#model_version:...,score_date:..."
// comment line, a "cve,epss,percentile" header, then data rows. Gzip input is
// detected by magic bytes.
func ParseEPSS(data []byte, fetchedAt time.Time) ([]EPSSRecord, string, error) {
	var r io.Reader = bytes.NewReader(data)
	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, "", fmt.Errorf("invalid gzip: %w", err)
		}
		defer func() { _ = gz.Close() }()
		r = gz
	}
	cr := csv.NewReader(r)
	cr.Comment = 0 // handled manually: the comment carries the feed version
	cr.FieldsPerRecord = -1

	version, scoreDate := "", ""
	var rows []EPSSRecord
	headerSeen := false
	for {
		row, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("invalid csv: %w", err)
		}
		if len(row) == 0 {
			continue
		}
		if strings.HasPrefix(row[0], "#") {
			for _, part := range append([]string{strings.TrimPrefix(row[0], "#")}, row[1:]...) {
				k, v, ok := strings.Cut(strings.TrimSpace(part), ":")
				if !ok {
					continue
				}
				switch k {
				case "model_version":
					version = v
				case "score_date":
					scoreDate = v
				}
			}
			continue
		}
		if !headerSeen {
			headerSeen = true
			if strings.EqualFold(row[0], "cve") {
				continue
			}
		}
		if len(row) < 3 {
			continue
		}
		score, err1 := strconv.ParseFloat(row[1], 64)
		pct, err2 := strconv.ParseFloat(row[2], 64)
		if err1 != nil || err2 != nil {
			continue
		}
		rows = append(rows, EPSSRecord{CVEID: strings.ToUpper(row[0]), Score: score, Percentile: pct})
	}
	if !headerSeen {
		return nil, "", errors.New("empty EPSS file")
	}
	feed := version
	if scoreDate != "" {
		feed += "@" + scoreDate
	}
	prov := Provenance{Source: SourceEPSS, FetchedAt: fetchedAt, FeedVersion: feed}
	for i := range rows {
		rows[i].ScoreDate = scoreDate
		rows[i].Provenance = prov
	}
	return rows, feed, nil
}
