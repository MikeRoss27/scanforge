package vulnintel

import (
	"context"
	"fmt"
	"time"
)

// maxNVDIncremental is NVD's limit for lastMod date ranges.
const maxNVDIncremental = 120 * 24 * time.Hour

// ValidSource reports whether name is a supported source.
func ValidSource(name string) bool {
	for _, s := range AllSources {
		if s == name {
			return true
		}
	}
	return false
}

// Update fetches the given sources (all when empty) and replaces the local
// cache. This is the only code path that performs network I/O. NVD updates
// are incremental when a previous fetch is recent enough, otherwise full.
// A failing source does not abort the others; the first error is returned
// after all were attempted.
func Update(ctx context.Context, store *Store, client *Client, sources []string) ([]SourceMeta, error) {
	if len(sources) == 0 {
		sources = AllSources
	}
	for _, s := range sources {
		if !ValidSource(s) {
			return nil, fmt.Errorf("unknown source %q (valid: nvd, kev, epss)", s)
		}
	}
	var done []SourceMeta
	var firstErr error
	for _, src := range sources {
		sm, err := updateOne(ctx, store, client, src)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s update failed: %w", src, err)
			}
			continue
		}
		done = append(done, sm)
	}
	return done, firstErr
}

func updateOne(ctx context.Context, store *Store, client *Client, src string) (SourceMeta, error) {
	fetchedAt := client.now()
	switch src {
	case SourceNVD:
		meta, err := store.ReadMeta()
		if err != nil {
			return SourceMeta{}, err
		}
		var since time.Time
		prev, hasPrev := meta.Sources[SourceNVD]
		if hasPrev && fetchedAt.Sub(prev.FetchedAt) < maxNVDIncremental && fetchedAt.After(prev.FetchedAt) {
			since = prev.FetchedAt
		}
		recs, feed, err := client.FetchNVD(ctx, since)
		if err != nil {
			return SourceMeta{}, err
		}
		if !since.IsZero() {
			var existing []CVERecord
			if err := readAll(store, SourceNVD, func(r CVERecord) { existing = append(existing, r) }); err != nil {
				return SourceMeta{}, err
			}
			recs = MergeCVEs(existing, recs)
		}
		sm := SourceMeta{Source: src, FetchedAt: fetchedAt, FeedVersion: feed}
		err = replace(store, &sm, recs)
		return sm, err
	case SourceKEV:
		recs, feed, err := client.FetchKEV(ctx)
		if err != nil {
			return SourceMeta{}, err
		}
		sm := SourceMeta{Source: src, FetchedAt: fetchedAt, FeedVersion: feed}
		err = replace(store, &sm, recs)
		return sm, err
	default:
		recs, feed, err := client.FetchEPSS(ctx)
		if err != nil {
			return SourceMeta{}, err
		}
		sm := SourceMeta{Source: src, FetchedAt: fetchedAt, FeedVersion: feed}
		err = replace(store, &sm, recs)
		return sm, err
	}
}
