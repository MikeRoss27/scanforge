package assets

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sort"
	"sync"

	"github.com/MikeRoss27/scanforge/internal/report"
)

// Focus decides which URLs the expensive active modules still need to look
// at in an incremental run. It implements modules.InputFocus. It only ever
// narrows an input that was already scope-filtered; unknown or uncertain
// URLs are always kept.
type Focus struct {
	hist        *History
	invalidated bool
	httpxPath   string

	once    sync.Once
	current map[string]string
	digest  string
}

// NewFocus builds a focus from a scope-filtered history. httpxPath is this
// run's httpx JSONL output, read lazily to detect changed services.
func NewFocus(h *History, invalidated bool, httpxPath string) *Focus {
	return &Focus{hist: h, invalidated: invalidated, httpxPath: httpxPath}
}

func (f *Focus) load() {
	f.once.Do(func() {
		f.current = map[string]string{}
		rep := report.NewReport("", "")
		if f.httpxPath != "" {
			_ = report.ParseHttpx(f.httpxPath, rep)
		}
		for _, asset := range rep.Assets {
			for _, svc := range asset.HTTP {
				f.current[svc.URL] = HTTPFingerprint(svc)
			}
		}
		h := sha256.New()
		_, _ = io.WriteString(h, boolStr(f.invalidated))
		keys := make([]string, 0, len(f.hist.Records))
		for k := range f.hist.Records {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			rec := f.hist.Records[k]
			if rec.Type != TypeURL && rec.Type != TypePath {
				continue
			}
			_, _ = io.WriteString(h, k+"\x00"+rec.Status+"\x00"+rec.Fingerprint+"\n")
		}
		urls := make([]string, 0, len(f.current))
		for u := range f.current {
			urls = append(urls, u)
		}
		sort.Strings(urls)
		for _, u := range urls {
			_, _ = io.WriteString(h, u+"\x00"+f.current[u]+"\n")
		}
		f.digest = hex.EncodeToString(h.Sum(nil))
	})
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// Keep reports whether value must be (re)scanned: it is new, previously
// gone, changed since the last run, or the cache is invalidated.
func (f *Focus) Keep(value string) bool {
	if f.invalidated {
		return true
	}
	f.load()
	rec, ok := f.hist.Lookup(TypeURL, value)
	if !ok {
		rec, ok = f.hist.Lookup(TypePath, value)
	}
	if !ok || rec.Status == StatusGone {
		return true
	}
	if fp, known := f.current[value]; known && rec.Fingerprint != "" && fp != rec.Fingerprint {
		return true
	}
	return false
}

// Digest identifies the focus inputs; it feeds the module input hash so a
// resumed run never reuses a result computed under another focus.
func (f *Focus) Digest() string {
	f.load()
	return f.digest
}
