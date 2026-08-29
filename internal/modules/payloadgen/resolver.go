package payloadgen

import (
	"net/url"
	"strings"
)

// endpointPath returns the path component of an absolute endpoint URL without
// the query string. The separation matters: api-paths.txt should contain clean
// paths (/users) while api-endpoints.txt keeps the full URL. Previously the
// function concatenated RawQuery, polluting the path wordlist.
func endpointPath(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Path == "" {
		return ""
	}
	return parsed.Path
}

// resolveEndpoint turns a possibly relative endpoint (e.g. "/api/users",
// "./api/users", "../api", "api/users", "v1/login") into an absolute URL
// using the JS file it was discovered in as the base.
//
// The original implementation rejected bare relative paths that did not start
// with "/", "./" or "../". Modern JS (fetch, axios, next.js) frequently uses
// bare paths like "api/users" or "v1/login", so those were silently dropped.
// The fix is to treat any non-absolute ref as relative to the JS file's
// directory and resolve it via url.ResolveReference, which already implements
// RFC 3986 reference resolution correctly.
//
// Absolute URLs (https://...) are returned as-is. Scheme-relative URLs
// (//cdn.example.com/lib.js) are resolved against the base scheme.
func resolveEndpoint(jsURL, endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" || strings.Contains(endpoint, " ") {
		return ""
	}
	base, err := url.Parse(jsURL)
	if err != nil || base.Hostname() == "" {
		return ""
	}
	ref, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	// Allow refs that are only a query string or fragment? No — require a path
	// component for a meaningful endpoint, but keep query-only refs if they have
	// a path-like prefix later. For empty Path but non-empty query, still reject
	// because endpointPath would be empty.
	if ref.Path == "" && ref.RawQuery == "" && ref.Fragment == "" {
		return ""
	}
	if ref.IsAbs() {
		return ref.String()
	}
	// Handle protocol-relative URLs: //example.com/foo
	if ref.Host != "" {
		// Inherit scheme from base.
		ref.Scheme = base.Scheme
		return ref.String()
	}
	// For any relative reference ("/api", "./api", "../api", "api/users"),
	// ResolveReference already does the right thing: it treats the base's path
	// as a file and resolves relative to its directory. No need to manually
	// mutate base.Path — that would double-count Dir.
	return base.ResolveReference(ref).String()
}
