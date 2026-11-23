package vulnintel

import (
	"sort"
	"strconv"
	"strings"
)

// Match quality labels, strongest first.
const (
	// QualityExactCPERange: the query CPE (vendor+product) equals the CVE's
	// CPE and the version falls in its range / equals its version.
	QualityExactCPERange = "exact-cpe-range"
	// QualityVersionRange: the product name equals the CPE product (after
	// normalization) and the version falls in the affected range.
	QualityVersionRange = "version-range"
	// QualityNameOnly: only a product-name similarity, or the CVE affects
	// all versions, or the version is unknown. Never confirmed.
	QualityNameOnly = "name-only"
)

// CPE is a parsed CPE 2.3 formatted string (only the fields we use).
type CPE struct {
	Part, Vendor, Product, Version string
}

// ParseCPE parses "cpe:2.3:a:vendor:product:version:...".
func ParseCPE(s string) (CPE, bool) {
	parts := splitCPE(s)
	if len(parts) < 6 || parts[0] != "cpe" || parts[1] != "2.3" {
		return CPE{}, false
	}
	return CPE{Part: parts[2], Vendor: strings.ToLower(parts[3]), Product: strings.ToLower(parts[4]), Version: parts[5]}, true
}

// splitCPE splits on unescaped colons.
func splitCPE(s string) []string {
	var parts []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			cur.WriteByte(s[i+1])
			i++
		case s[i] == ':':
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(s[i])
		}
	}
	return append(parts, cur.String())
}

// Query describes what was fingerprinted.
type Query struct {
	Product string
	Version string
	CPE     string // optional CPE 2.3 string
}

// Candidate is a possible CVE for a query. Confirmed is true only when the
// version was actually matched against the CVE's affected range; a name-only
// candidate is never confirmed. Even a confirmed candidate is a banner-based
// inference, not proof of exploitability.
type Candidate struct {
	CVEID          string  `json:"cve_id"`
	Description    string  `json:"description,omitempty"`
	Severity       string  `json:"severity,omitempty"`
	CVSS           float64 `json:"cvss,omitempty"`
	Quality        string  `json:"match_quality"`
	Confirmed      bool    `json:"confirmed"`
	MatchedCPE     string  `json:"matched_cpe,omitempty"`
	KEV            bool    `json:"kev,omitempty"`
	EPSS           float64 `json:"epss,omitempty"`
	EPSSPercentile float64 `json:"epss_percentile,omitempty"`
	Provenance     `json:"provenance"`
}

func qualityRank(q string) int {
	switch q {
	case QualityExactCPERange:
		return 0
	case QualityVersionRange:
		return 1
	}
	return 2
}

// productAliases maps fingerprint names to CPE product names.
var productAliases = map[string]string{
	"apache":             "http_server",
	"httpd":              "http_server",
	"apache_http_server": "http_server",
	"tomcat":             "tomcat",
	"apache_tomcat":      "tomcat",
	"apachetomcat":       "tomcat",
	"jqueryui":           "jquery_ui",
	"microsoft_iis":      "internet_information_services",
	"iis":                "internet_information_services",
}

// NormalizeProduct lowercases and maps separators to underscores.
func NormalizeProduct(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.Join(strings.FieldsFunc(n, func(r rune) bool { return r == ' ' || r == '-' || r == '_' }), "_")
	if a, ok := productAliases[n]; ok {
		return a
	}
	return n
}

// productRelation: 2 exact, 1 similar (substring on token boundary), 0 none.
func productRelation(query, cpeProduct string) int {
	q, p := NormalizeProduct(query), strings.ToLower(cpeProduct)
	switch {
	case q == "" || p == "":
		return 0
	case q == p:
		return 2
	case strings.Contains(p, q) || strings.Contains(q, p):
		return 1
	}
	return 0
}

func versionKnown(v string) bool {
	return v != "" && v != "*" && v != "-" && v[0] >= '0' && v[0] <= '9'
}

// hasBounds reports whether the match carries a version range.
func (m CPEMatch) hasBounds() bool {
	return m.StartIncl != "" || m.StartExcl != "" || m.EndIncl != "" || m.EndExcl != ""
}

// versionIn evaluates version against the match. ok=false means the match
// carries no version information (all versions), so nothing was verified.
func (m CPEMatch) versionIn(version string) (in, ok bool) {
	if m.hasBounds() {
		if m.StartIncl != "" && CompareVersions(version, m.StartIncl) < 0 {
			return false, true
		}
		if m.StartExcl != "" && CompareVersions(version, m.StartExcl) <= 0 {
			return false, true
		}
		if m.EndIncl != "" && CompareVersions(version, m.EndIncl) > 0 {
			return false, true
		}
		if m.EndExcl != "" && CompareVersions(version, m.EndExcl) >= 0 {
			return false, true
		}
		return true, true
	}
	if versionKnown(m.Version) {
		return CompareVersions(version, m.Version) == 0, true
	}
	return false, false
}

// CompareVersions compares dotted numeric versions; non-numeric separators
// are ignored and missing segments count as 0.
func CompareVersions(a, b string) int {
	as, bs := numericParts(a), numericParts(b)
	for i := 0; i < len(as) || i < len(bs); i++ {
		var av, bv int
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

func numericParts(v string) []int {
	var out []int
	for _, p := range strings.FieldsFunc(v, func(r rune) bool { return r < '0' || r > '9' }) {
		if n, err := strconv.Atoi(p); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// evaluate returns the best quality of cve for the query, or "" for no match.
func evaluate(rec *CVERecord, q Query, qcpe CPE, hasCPE bool, version string) (quality, matched string) {
	best := ""
	bestCPE := ""
	consider := func(quality, cpe string) {
		if best == "" || qualityRank(quality) < qualityRank(best) {
			best, bestCPE = quality, cpe
		}
	}
	for _, m := range rec.Matches {
		if hasCPE {
			if m.Vendor == qcpe.Vendor && m.Product == qcpe.Product {
				if !versionKnown(version) {
					consider(QualityNameOnly, m.Criteria)
					continue
				}
				in, ok := m.versionIn(version)
				switch {
				case !ok:
					consider(QualityNameOnly, m.Criteria)
				case in:
					consider(QualityExactCPERange, m.Criteria)
				}
				continue
			}
		}
		rel := productRelation(q.Product, m.Product)
		if rel == 0 {
			continue
		}
		if hasCPE && rel == 2 {
			rel = 1 // same product name under another vendor: similarity only
		}
		if rel == 1 || !versionKnown(version) {
			consider(QualityNameOnly, m.Criteria)
			continue
		}
		in, ok := m.versionIn(version)
		switch {
		case !ok:
			consider(QualityNameOnly, m.Criteria)
		case in:
			consider(QualityVersionRange, m.Criteria)
		}
	}
	return best, bestCPE
}

// DB is the in-memory view of the local cache. It is read-only and offline.
type DB struct {
	byProduct map[string][]*CVERecord
	kev       map[string]KEVRecord
	epss      map[string]EPSSRecord
	Meta      Meta
}

// Load reads the cache into memory. A missing cache yields an empty DB.
func Load(store *Store) (*DB, error) {
	meta, err := store.ReadMeta()
	if err != nil {
		return nil, err
	}
	db := &DB{byProduct: map[string][]*CVERecord{}, kev: map[string]KEVRecord{}, epss: map[string]EPSSRecord{}, Meta: meta}
	err = readAll(store, SourceNVD, func(r CVERecord) {
		rec := r
		seen := map[string]bool{}
		for _, m := range rec.Matches {
			if !seen[m.Product] {
				seen[m.Product] = true
				db.byProduct[m.Product] = append(db.byProduct[m.Product], &rec)
			}
		}
	})
	if err != nil {
		return nil, err
	}
	if err := readAll(store, SourceKEV, func(r KEVRecord) { db.kev[r.CVEID] = r }); err != nil {
		return nil, err
	}
	if err := readAll(store, SourceEPSS, func(r EPSSRecord) { db.epss[r.CVEID] = r }); err != nil {
		return nil, err
	}
	return db, nil
}

// OpenIfPresent loads the default cache and returns nil when none exists
// (or it cannot be read), so callers can fall back to bundled data.
func OpenIfPresent() *DB {
	store, err := OpenDefault()
	if err != nil || !store.HasData() {
		return nil
	}
	db, err := Load(store)
	if err != nil || len(db.byProduct) == 0 {
		return nil
	}
	return db
}

// Match returns candidate CVEs for a product/version/cpe. Candidates are
// ordered by quality, then KEV, then EPSS. Name-only candidates are returned
// (so callers can display them as leads) but are never Confirmed.
func (db *DB) Match(q Query) []Candidate {
	qcpe, hasCPE := ParseCPE(q.CPE)
	version := q.Version
	if version == "" && hasCPE {
		version = qcpe.Version
	}
	product := NormalizeProduct(q.Product)
	if hasCPE && product == "" {
		product = qcpe.Product
		q.Product = product
	}
	if product == "" {
		return nil
	}

	// Gather candidate records: products equal to / similar to the query.
	records := map[string]*CVERecord{}
	add := func(p string) {
		for _, r := range db.byProduct[p] {
			records[r.ID] = r
		}
	}
	if hasCPE {
		add(qcpe.Product)
	}
	for p := range db.byProduct {
		if productRelation(q.Product, p) > 0 {
			add(p)
		}
	}

	var out []Candidate
	for _, rec := range records {
		quality, matched := evaluate(rec, q, qcpe, hasCPE, version)
		if quality == "" {
			continue
		}
		c := Candidate{
			CVEID: rec.ID, Description: rec.Description, Severity: rec.Severity, CVSS: rec.CVSS,
			Quality: quality, Confirmed: quality != QualityNameOnly, MatchedCPE: matched, Provenance: rec.Provenance,
		}
		_, c.KEV = db.kev[rec.ID]
		if e, ok := db.epss[rec.ID]; ok {
			c.EPSS, c.EPSSPercentile = e.Score, e.Percentile
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if qa, qb := qualityRank(a.Quality), qualityRank(b.Quality); qa != qb {
			return qa < qb
		}
		if a.KEV != b.KEV {
			return a.KEV
		}
		if a.EPSS != b.EPSS {
			return a.EPSS > b.EPSS
		}
		return a.CVEID < b.CVEID
	})
	return out
}
