package runindex

import (
	"encoding/json"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Redacted replaces the operator's own credentials in any output.
const Redacted = "[REDACTED-OPERATOR-SECRET]"

const minSecretLen = 6

// Scrubber masks exact occurrences of the OPERATOR's credentials (API keys,
// auth cookies/tokens, headers handed to scans). It deliberately never
// pattern-masks secrets found on the target: those are bounty evidence.
type Scrubber struct {
	values []string
}

// NewScrubber builds a scrubber from raw secret values. Short values are
// ignored to avoid shredding unrelated text.
func NewScrubber(values ...string) *Scrubber {
	s := &Scrubber{}
	s.Add(values...)
	return s
}

// Add registers more secret values (plus their JSON-escaped forms).
func (s *Scrubber) Add(values ...string) {
	seen := map[string]bool{}
	for _, v := range s.values {
		seen[v] = true
	}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if len(v) < minSecretLen {
			continue
		}
		forms := []string{v}
		if enc, err := json.Marshal(v); err == nil && len(enc) > 2 {
			if esc := string(enc[1 : len(enc)-1]); esc != v {
				forms = append(forms, esc)
			}
		}
		for _, f := range forms {
			if !seen[f] {
				seen[f] = true
				s.values = append(s.values, f)
			}
		}
	}
	sort.Slice(s.values, func(i, j int) bool { return len(s.values[i]) > len(s.values[j]) })
}

// Clone returns an independent copy.
func (s *Scrubber) Clone() *Scrubber {
	c := &Scrubber{}
	if s != nil {
		c.values = append(c.values, s.values...)
	}
	return c
}

// Apply returns text with every known operator secret masked.
func (s *Scrubber) Apply(text string) string {
	if s == nil {
		return text
	}
	for _, v := range s.values {
		text = strings.ReplaceAll(text, v, Redacted)
	}
	return text
}

var (
	headerTokenRE = regexp.MustCompile(`(?i)^\s*(authorization|proxy-authorization|cookie|x-[a-z0-9-]*(?:key|token|auth|secret)[a-z0-9-]*|[a-z0-9-]*(?:api-?key|token|secret))\s*:\s*(.+)$`)
	urlUserinfoRE = regexp.MustCompile(`://[^/\s:@'"]+:([^@\s/'"]+)@`)
)

// secretsFromCommandLog extracts the operator's header values (-H "Cookie: ...")
// and proxy credentials from a run's commands.log, which records full command
// lines. The values feed the scrubber; the log itself is never served.
func secretsFromCommandLog(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	data, _ := io.ReadAll(io.LimitReader(f, 4<<20))
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		for _, m := range urlUserinfoRE.FindAllStringSubmatch(line, -1) {
			out = append(out, m[1])
		}
		for _, tok := range shellTokens(line) {
			m := headerTokenRE.FindStringSubmatch(tok)
			if m == nil {
				continue
			}
			out = append(out, headerValueSecrets(m[1], strings.TrimSpace(m[2]))...)
		}
	}
	return out
}

func headerValueSecrets(name, value string) []string {
	out := []string{value}
	for _, scheme := range []string{"Bearer ", "Basic ", "Token "} {
		if len(value) > len(scheme) && strings.EqualFold(value[:len(scheme)], scheme) {
			out = append(out, value[len(scheme):])
		}
	}
	if strings.EqualFold(name, "cookie") {
		for _, pair := range strings.Split(value, ";") {
			if _, v, ok := strings.Cut(strings.TrimSpace(pair), "="); ok {
				out = append(out, v)
			}
		}
	}
	return out
}

// shellTokens splits a line using the quoting conventions of
// runner.AppendCommandLog (single quotes, embedded quote as '\”).
func shellTokens(line string) []string {
	var toks []string
	var cur strings.Builder
	var quote rune
	inTok := false
	rs := []rune(line)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else if r == '\\' && quote == '"' && i+1 < len(rs) {
				i++
				cur.WriteRune(rs[i])
			} else {
				cur.WriteRune(r)
			}
		case r == '\\' && i+1 < len(rs) && rs[i+1] == '\'':
			cur.WriteRune('\'')
			i++
			inTok = true
		case r == '\'' || r == '"':
			quote, inTok = r, true
		case r == ' ' || r == '\t':
			if inTok {
				toks = append(toks, cur.String())
				cur.Reset()
				inTok = false
			}
		default:
			cur.WriteRune(r)
			inTok = true
		}
	}
	if inTok {
		toks = append(toks, cur.String())
	}
	return toks
}
