package dbcore

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// makeJWT builds a syntactically valid JWT whose payload carries the given
// claims, so the role/iss classifier can be exercised without a live key.
func makeJWT(t *testing.T, claims map[string]string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	sig := base64.RawURLEncoding.EncodeToString([]byte("signature-not-verified"))
	return header + "." + payload + "." + sig
}

func TestClassifyKey(t *testing.T) {
	anonJWT := makeJWT(t, map[string]string{"role": "anon", "iss": "supabase"})
	serviceJWT := makeJWT(t, map[string]string{"role": "service_role", "iss": "supabase"})
	unrelatedJWT := makeJWT(t, map[string]string{"sub": "user-123", "name": "alice"})

	tests := []struct {
		name     string
		raw      string
		wantOK   bool
		wantType string
		wantSev  string
		wantPub  bool
	}{
		{"supabase secret", "sb_secret_0123456789abcdefghij", true, "supabase-secret", "critical", false},
		{"supabase publishable", "sb_publishable_0123456789abcdefghij", true, "supabase-publishable", "info", true},
		{"firebase api key", "AIzaSyB1234567890abcdefghijklmnopqrstuv", true, "firebase-api-key", "info", true},
		{"supabase anon jwt", anonJWT, true, "supabase-anon-jwt", "info", true},
		{"supabase service role jwt", serviceJWT, true, "supabase-service-role-jwt", "critical", false},
		{"unrelated jwt", unrelatedJWT, false, "", "", false},
		{"not a key", "hello world", false, "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			class, ok := ClassifyKey(tc.raw)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if class.Type != tc.wantType || class.Severity != tc.wantSev || class.Public != tc.wantPub {
				t.Fatalf("got %+v, want type=%s sev=%s pub=%v", class, tc.wantType, tc.wantSev, tc.wantPub)
			}
		})
	}
}

func TestRedact(t *testing.T) {
	got := Redact("sb_secret_0123456789abcdefWXYZ")
	if got != "sb_s…WXYZ" {
		t.Fatalf("Redact = %q", got)
	}
	if Redact("short") != "****" {
		t.Fatalf("short key not fully redacted: %q", Redact("short"))
	}
	// A secret value must never survive redaction in full.
	if Redact("sb_secret_0123456789abcdefWXYZ") == "sb_secret_0123456789abcdefWXYZ" {
		t.Fatal("redaction left the key intact")
	}
}

func TestDetectFixtures(t *testing.T) {
	tests := []struct {
		file         string
		wantBackend  Backend
		wantHost     string
		wantEndpoint string
		wantKeyType  string
		wantKeySev   string
		wantKeyKept  bool // KeyValue persisted (public key)
	}{
		{"supabase.js", Supabase, "abcdefghijklmnopqrst.supabase.co", "https://abcdefghijklmnopqrst.supabase.co", "supabase-publishable", "info", true},
		{"appwrite.js", Appwrite, "fra.cloud.appwrite.io", "https://fra.cloud.appwrite.io/v1", "", "", false},
		{"pocketbase.js", PocketBase, "pb.example.com", "https://pb.example.com", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join("testdata", tc.file))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			records := Detect("https://app.example.com/"+tc.file, body)
			var found *FingerprintRecord
			for i := range records {
				if records[i].Backend == string(tc.wantBackend) {
					found = &records[i]
					break
				}
			}
			if found == nil {
				t.Fatalf("no %s record in %+v", tc.wantBackend, records)
			}
			if found.Host != tc.wantHost {
				t.Errorf("host = %q, want %q", found.Host, tc.wantHost)
			}
			if found.Endpoint != tc.wantEndpoint {
				t.Errorf("endpoint = %q, want %q", found.Endpoint, tc.wantEndpoint)
			}
			if found.KeyType != tc.wantKeyType {
				t.Errorf("key type = %q, want %q", found.KeyType, tc.wantKeyType)
			}
			if found.KeySeverity != tc.wantKeySev {
				t.Errorf("key severity = %q, want %q", found.KeySeverity, tc.wantKeySev)
			}
			if (found.KeyValue != "") != tc.wantKeyKept {
				t.Errorf("KeyValue kept = %v (%q), want %v", found.KeyValue != "", found.KeyValue, tc.wantKeyKept)
			}
		})
	}
}

func TestDetectFirebaseEndpoints(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("testdata", "firebase.js"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	records := Detect("https://app.example.com/firebase.js", body)
	hosts := map[string]bool{}
	for _, r := range records {
		if r.Backend != string(Firebase) {
			continue
		}
		hosts[r.Host] = true
		if r.KeyType != "firebase-api-key" {
			t.Errorf("firebase record missing api key: %+v", r)
		}
		if r.KeyValue == "" {
			t.Errorf("public firebase api key should be persisted: %+v", r)
		}
	}
	for _, want := range []string{"my-app-12345-default-rtdb.firebaseio.com", "my-app-12345.firebaseapp.com"} {
		if !hosts[want] {
			t.Errorf("missing firebase host %q (got %v)", want, hosts)
		}
	}
}

func TestDetectServiceRoleRedacted(t *testing.T) {
	service := makeJWT(t, map[string]string{"role": "service_role", "iss": "supabase"})
	js := `const url="https://projectref0000000000.supabase.co";const key="` + service + `";`
	records := Detect("https://app.example.com/leak.js", []byte(js))
	if len(records) == 0 {
		t.Fatal("expected a supabase record")
	}
	rec := records[0]
	if rec.KeySeverity != "critical" {
		t.Fatalf("service_role key should be critical, got %q", rec.KeySeverity)
	}
	if rec.KeyValue != "" {
		t.Fatal("service_role key must not be persisted in full")
	}
	if rec.KeyRedacted == "" || rec.KeyRedacted == service {
		t.Fatalf("service_role key must be redacted, got %q", rec.KeyRedacted)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "db-fingerprint.jsonl")
	want := []FingerprintRecord{
		{Target: "a.example.com", Backend: "supabase", Endpoint: "https://ref.supabase.co", Host: "ref.supabase.co", KeyType: "supabase-publishable", KeySeverity: "info"},
		{Target: "a.example.com", Backend: "appwrite", Endpoint: "https://cloud.appwrite.io/v1", Host: "cloud.appwrite.io"},
	}
	if err := Save(path, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("round trip got %d records, want %d", len(got), len(want))
	}
	if got[0].Host != want[0].Host || got[1].Backend != want[1].Backend {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestLoadMissingFile(t *testing.T) {
	records, err := Load(filepath.Join(t.TempDir(), "does-not-exist.jsonl"))
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if records != nil {
		t.Fatalf("missing file should yield nil, got %v", records)
	}
}
