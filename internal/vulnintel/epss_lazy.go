package vulnintel

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
)

// epssSpan locates one JSONL line of the EPSS cache.
type epssSpan struct {
	off int64
	len int32
}

// epssIDPrefix is how encoding/json writes an EPSSRecord (cve_id is its first
// field), which lets the index read the ID without decoding the whole line.
var epssIDPrefix = []byte(`{"cve_id":"`)

// epssFor returns the EPSS rows of the requested CVE IDs. The index over the
// cache file is built once, lazily, on the first call that has IDs to look
// up; only the requested lines are decoded. Offline and best-effort: a
// missing or unreadable cache yields no scores, so matching never fails
// because of EPSS.
func (db *DB) epssFor(ids []string) map[string]EPSSRecord {
	if db == nil || db.epssStore == nil || len(ids) == 0 {
		return nil
	}
	path := db.epssStore.file(SourceEPSS)
	db.epssOnce.Do(func() { db.epssIdx = indexEPSS(path) })
	if len(db.epssIdx) == 0 {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	out := make(map[string]EPSSRecord, len(ids))
	var buf []byte
	for _, id := range ids {
		span, ok := db.epssIdx[id]
		if !ok {
			continue
		}
		if int(span.len) > cap(buf) {
			buf = make([]byte, span.len)
		}
		line := buf[:span.len]
		if _, err := f.ReadAt(line, span.off); err != nil && !errors.Is(err, io.EOF) {
			continue
		}
		var rec EPSSRecord
		if json.Unmarshal(line, &rec) == nil && rec.CVEID == id {
			out[id] = rec
		}
	}
	return out
}

// indexEPSS maps each CVE ID of the JSONL file to its line span. A later line
// for the same ID wins, matching the previous eager load.
func indexEPSS(path string) map[string]epssSpan {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	idx := make(map[string]epssSpan, 1<<18)
	r := bufio.NewReaderSize(f, 1<<20)
	var off int64
	for {
		line, err := r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			// Pathologically long line: keep the whole thing.
			rest, rerr := r.ReadBytes('\n')
			line = append(append([]byte(nil), line...), rest...)
			err = rerr
		}
		if n := len(line); n > 0 {
			body := bytes.TrimRight(line, "\r\n")
			if id := epssLineID(body); id != "" {
				idx[id] = epssSpan{off: off, len: int32(len(body))}
			}
			off += int64(n)
		}
		if err != nil {
			return idx
		}
	}
}

func epssLineID(line []byte) string {
	if len(line) == 0 {
		return ""
	}
	if bytes.HasPrefix(line, epssIDPrefix) {
		rest := line[len(epssIDPrefix):]
		if end := bytes.IndexByte(rest, '"'); end > 0 && bytes.IndexByte(rest[:end], '\\') < 0 {
			return string(rest[:end])
		}
	}
	var rec struct {
		CVEID string `json:"cve_id"`
	}
	if json.Unmarshal(line, &rec) != nil {
		return ""
	}
	return rec.CVEID
}
