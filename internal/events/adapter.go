package events

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ArtifactEventTypes maps line-oriented artifact names to the event type
// their lines represent. Only the demo mapping lives here; extend as modules
// opt in.
var ArtifactEventTypes = map[string]Type{
	"subdomains": DNSName,
}

// EmitLines publishes one root event of type t per non-empty line of the
// file at path, attributed to source. Per-line dispositions (duplicate, out
// of scope, ...) are not errors; the first hard error (I/O, persistence)
// stops emission and is returned. published counts delivered events.
func EmitLines(b *Bus, path string, t Type, source string) (published int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("events: open %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		disp, err := b.Publish(Event{Type: t, Value: line, Source: source})
		if err != nil {
			return published, err
		}
		if disp == Delivered {
			published++
		}
	}
	if err := sc.Err(); err != nil {
		return published, fmt.Errorf("events: read %q: %w", path, err)
	}
	return published, nil
}
