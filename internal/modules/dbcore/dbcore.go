// Package dbcore holds the shared backend-as-a-service (BaaS) fingerprint
// schema and detection signatures used by the dbdetect module (passive) and,
// later, the active enumeration module. Keeping the signatures and the
// FingerprintRecord schema in one place guarantees the writer and the future
// reader cannot drift apart.
//
// Detection is strictly passive: Detect only inspects bytes the caller already
// fetched from the target's own pages/JS. It never contacts a backend.
package dbcore

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// OutputDir is where dbdetect writes its fingerprint artifact.
const OutputDir = "06_vulns"

// Backend identifies a backend-as-a-service provider.
type Backend string

const (
	Supabase   Backend = "supabase"
	Firebase   Backend = "firebase"
	Appwrite   Backend = "appwrite"
	PocketBase Backend = "pocketbase"
)

// FingerprintRecord is one line of db-fingerprint.jsonl. One record is emitted
// per distinct (backend, endpoint, key-type) discovered across the scanned
// pages. Key material is only persisted in full when it is public by design
// (an anon / publishable key); secret keys are stored redacted so a scan
// artifact never leaks a working service-role credential to disk.
type FingerprintRecord struct {
	Target      string `json:"target"`                 // host of the page the backend was found on
	Backend     string `json:"backend"`                // supabase/firebase/appwrite/pocketbase
	Endpoint    string `json:"endpoint"`               // project base URL, e.g. https://ref.supabase.co
	Host        string `json:"host"`                   // backend host, e.g. ref.supabase.co (scope + enumeration)
	KeyType     string `json:"key_type,omitempty"`     // e.g. supabase-anon-jwt, supabase-secret
	KeySeverity string `json:"key_severity,omitempty"` // info / medium / critical
	KeyRedacted string `json:"key_redacted,omitempty"` // first4…last4, always safe to show
	KeyValue    string `json:"key_value,omitempty"`    // full value, ONLY when public by design
	EvidenceURL string `json:"evidence_url"`           // page/JS URL the signal came from
	FetchedAt   string `json:"fetched_at,omitempty"`
}

// KeyClass is the result of classifying a key-shaped string found in client
// code.
type KeyClass struct {
	Type     string // stable identifier, e.g. "supabase-service-role-jwt"
	Severity string // info / medium / critical
	Public   bool   // true when the key is public by design (safe to persist)
}

// signature identifies one backend from a regex over page/JS bytes and
// extracts its endpoint. Adding a backend is a matter of appending signatures.
type signature struct {
	backend Backend
	name    string
	re      *regexp.Regexp
	// endpoint turns a regex submatch into a project base URL (or host). An
	// empty return discards the match.
	endpoint func(match []string) string
}

var (
	// Supabase: https://<ref>.supabase.{co,in,net}. The ref is ~20 lowercase
	// alphanumerics; stay lenient but anchored to the supabase apex.
	supabaseHostRe = regexp.MustCompile(`https?://([a-z0-9]{16,40})\.supabase\.(?:co|in|net)`)

	// Firebase Realtime Database URLs and the firebaseConfig object.
	firebaseRTDBRe = regexp.MustCompile(`https?://([a-z0-9][a-z0-9\-]{2,})\.(?:firebaseio\.com|firebasedatabase\.app)`)
	// authDomain is usually a bare host in firebaseConfig, so the scheme is
	// optional here.
	firebaseAppRe = regexp.MustCompile(`(?:https?://)?([a-z0-9][a-z0-9\-]{2,})\.firebaseapp\.com`)

	// Appwrite Cloud and self-hosted endpoints both expose a /v1 base.
	appwriteCloudRe = regexp.MustCompile(`https?://(?:[a-z0-9\-]+\.)?(?:cloud\.)?appwrite\.io/v1`)

	// PocketBase client init: new PocketBase('https://...').
	pocketbaseInitRe = regexp.MustCompile(`new\s+PocketBase\(\s*['"](https?://[^'"]+)['"]`)
)

// signatures is the ordered detection table. Order only affects which evidence
// is recorded first; dedup happens in the caller.
var signatures = []signature{
	{Supabase, "supabase-host", supabaseHostRe, func(m []string) string {
		return "https://" + m[1] + ".supabase.co"
	}},
	{Firebase, "firebase-rtdb", firebaseRTDBRe, func(m []string) string {
		return m[0]
	}},
	{Firebase, "firebase-app", firebaseAppRe, func(m []string) string {
		return "https://" + m[1] + ".firebaseapp.com"
	}},
	{Appwrite, "appwrite-cloud", appwriteCloudRe, func(m []string) string {
		return strings.TrimSuffix(m[0], "/")
	}},
	{PocketBase, "pocketbase-init", pocketbaseInitRe, func(m []string) string {
		return strings.TrimRight(m[1], "/")
	}},
}

// Key-shaped patterns scanned across the same bytes. Each match is classified
// by ClassifyKey; non-backend JWTs are discarded there.
var keyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`sb_secret_[A-Za-z0-9_\-]{16,}`),
	regexp.MustCompile(`sb_publishable_[A-Za-z0-9_\-]{16,}`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`),
	regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`),
}

// ClassifyKey categorizes a key-shaped string. ok is false when the value is
// not a recognizable backend key (e.g. an unrelated JWT), so callers skip it.
func ClassifyKey(raw string) (KeyClass, bool) {
	switch {
	case strings.HasPrefix(raw, "sb_secret_"):
		return KeyClass{Type: "supabase-secret", Severity: "critical", Public: false}, true
	case strings.HasPrefix(raw, "sb_publishable_"):
		return KeyClass{Type: "supabase-publishable", Severity: "info", Public: true}, true
	case strings.HasPrefix(raw, "AIza"):
		// Firebase/Google API keys are public identifiers, not secrets, but a
		// locked-down key still matters for inventory.
		return KeyClass{Type: "firebase-api-key", Severity: "info", Public: true}, true
	case strings.HasPrefix(raw, "eyJ"):
		role, iss, ok := jwtRoleIss(raw)
		if !ok {
			return KeyClass{}, false
		}
		isSupabase := role == "anon" || role == "service_role" || strings.Contains(iss, "supabase")
		if !isSupabase {
			return KeyClass{}, false
		}
		if role == "service_role" {
			return KeyClass{Type: "supabase-service-role-jwt", Severity: "critical", Public: false}, true
		}
		return KeyClass{Type: "supabase-anon-jwt", Severity: "info", Public: true}, true
	}
	return KeyClass{}, false
}

// jwtRoleIss decodes a JWT payload and returns its role and iss claims. ok is
// false when the payload is not decodable JSON.
func jwtRoleIss(token string) (role, iss string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Some encoders pad; try standard URL encoding too.
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return "", "", false
		}
	}
	var claims struct {
		Role string `json:"role"`
		Iss  string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", "", false
	}
	return claims.Role, claims.Iss, true
}

// Redact renders a key-shaped value safe to display and store: first four and
// last four characters, everything else elided.
func Redact(raw string) string {
	r := []rune(raw)
	if len(r) <= 8 {
		return "****"
	}
	return string(r[:4]) + "…" + string(r[len(r)-4:])
}

// Detect scans one page/JS body and returns a fingerprint record per
// (backend, endpoint, key) signal found. Target/EvidenceURL are set from
// evidenceURL; FetchedAt is left to the caller. The function performs no I/O
// and never contacts any backend.
func Detect(evidenceURL string, body []byte) []FingerprintRecord {
	text := string(body)
	target := hostOf(evidenceURL)

	// Classify every key once; attach the most relevant keys per endpoint.
	keys := scanKeys(text)

	// Endpoints found, in first-seen order, deduplicated.
	type ep struct {
		backend  Backend
		endpoint string
		host     string
	}
	var endpoints []ep
	seen := map[string]bool{}
	for _, sig := range signatures {
		for _, m := range sig.re.FindAllStringSubmatch(text, -1) {
			endpoint := sig.endpoint(m)
			if endpoint == "" {
				continue
			}
			host := hostOf(endpoint)
			if host == "" {
				continue
			}
			k := string(sig.backend) + "|" + host
			if seen[k] {
				continue
			}
			seen[k] = true
			endpoints = append(endpoints, ep{sig.backend, endpoint, host})
		}
	}

	var records []FingerprintRecord
	for _, e := range endpoints {
		base := FingerprintRecord{
			Target:      target,
			Backend:     string(e.backend),
			Endpoint:    e.endpoint,
			Host:        e.host,
			EvidenceURL: evidenceURL,
		}
		matched := keysForBackend(keys, e.backend)
		if len(matched) == 0 {
			records = append(records, base)
			continue
		}
		for _, k := range matched {
			rec := base
			rec.KeyType = k.class.Type
			rec.KeySeverity = k.class.Severity
			rec.KeyRedacted = Redact(k.raw)
			if k.class.Public {
				rec.KeyValue = k.raw
			}
			records = append(records, rec)
		}
	}
	return records
}

type scannedKey struct {
	raw   string
	class KeyClass
}

func scanKeys(text string) []scannedKey {
	var out []scannedKey
	seen := map[string]bool{}
	for _, re := range keyPatterns {
		for _, raw := range re.FindAllString(text, -1) {
			if seen[raw] {
				continue
			}
			seen[raw] = true
			if class, ok := ClassifyKey(raw); ok {
				out = append(out, scannedKey{raw: raw, class: class})
			}
		}
	}
	return out
}

// keysForBackend returns the keys that belong to a given backend, so a
// Supabase JWT is not attached to a co-located Firebase endpoint.
func keysForBackend(keys []scannedKey, backend Backend) []scannedKey {
	var out []scannedKey
	for _, k := range keys {
		if keyBackend(k.class.Type) == backend {
			out = append(out, k)
		}
	}
	return out
}

func keyBackend(keyType string) Backend {
	switch {
	case strings.HasPrefix(keyType, "supabase"):
		return Supabase
	case strings.HasPrefix(keyType, "firebase"):
		return Firebase
	}
	return ""
}

func hostOf(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		// Bare host[:port].
		if i := strings.IndexByte(raw, '/'); i >= 0 {
			raw = raw[:i]
		}
		return strings.ToLower(raw)
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

// Save writes records as JSONL, truncating any existing file.
func Save(path string, records []FingerprintRecord) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	w := bufio.NewWriter(file)
	enc := json.NewEncoder(w)
	for _, rec := range records {
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return w.Flush()
}

// Load reads a db-fingerprint.jsonl file. A missing file yields no records.
func Load(path string) ([]FingerprintRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var items []FingerprintRecord
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var item FingerprintRecord
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			continue
		}
		items = append(items, item)
	}
	return items, scanner.Err()
}
