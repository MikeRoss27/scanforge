package dbenum

import "testing"

func TestParseOpenAPITables(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "definitions preferred",
			body: `{"swagger":"2.0","definitions":{"users":{},"orders":{},"profiles":{}},"paths":{"/":{}}}`,
			want: []string{"orders", "profiles", "users"},
		},
		{
			name: "paths fallback",
			body: `{"swagger":"2.0","paths":{"/":{},"/customers":{},"/rpc/do_thing":{},"/{id}":{}}}`,
			want: []string{"customers"},
		},
		{"empty", `{}`, nil},
		{"garbage", `not json`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseOpenAPITables([]byte(tt.body))
			if len(got) != len(tt.want) {
				t.Fatalf("got %v want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v want %v", got, tt.want)
				}
			}
		})
	}
}

func TestParseContentRangeCount(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"0-24/573", 573},
		{"*/42", 42},
		{"0-0/0", 0},
		{"*/*", -1},
		{"", -1},
		{"weird", -1},
	}
	for _, tt := range tests {
		if got := parseContentRangeCount(tt.in); got != tt.want {
			t.Errorf("parseContentRangeCount(%q)=%d want %d", tt.in, got, tt.want)
		}
	}
}

func TestParseAuthSettings(t *testing.T) {
	providers, disabled := parseAuthSettings([]byte(`{"external":{"github":true,"google":true,"apple":false},"disable_signup":false}`))
	if len(providers) != 2 || providers[0] != "github" || providers[1] != "google" {
		t.Fatalf("providers=%v", providers)
	}
	if disabled {
		t.Fatalf("disable_signup should be false")
	}
}

func TestCountTopLevelKeysAndReadable(t *testing.T) {
	if n := countTopLevelKeys([]byte(`{"a":true,"b":true,"c":true}`)); n != 3 {
		t.Fatalf("keys=%d", n)
	}
	if n := countTopLevelKeys([]byte(`true`)); n != 1 {
		t.Fatalf("scalar should count 1, got %d", n)
	}
	for _, c := range []struct {
		body string
		want bool
	}{
		{`{"a":true}`, true},
		{`"value"`, true},
		{`null`, false},
		{`{}`, false},
		{``, false},
	} {
		if got := looksReadable([]byte(c.body)); got != c.want {
			t.Errorf("looksReadable(%q)=%v want %v", c.body, got, c.want)
		}
	}
}

func TestParsePocketBaseTotal(t *testing.T) {
	if n := parsePocketBaseTotal([]byte(`{"page":1,"perPage":1,"totalItems":128,"items":[]}`)); n != 128 {
		t.Fatalf("total=%d", n)
	}
	if n := parsePocketBaseTotal([]byte(`{"items":[]}`)); n != -1 {
		t.Fatalf("missing total should be -1, got %d", n)
	}
}

func TestIsRTDBHost(t *testing.T) {
	for _, c := range []struct {
		host string
		want bool
	}{
		{"proj-default-rtdb.firebaseio.com", true},
		{"proj.europe-west1.firebasedatabase.app", true},
		{"proj.firebaseapp.com", false},
		{"example.com", false},
	} {
		if got := isRTDBHost(c.host); got != c.want {
			t.Errorf("isRTDBHost(%q)=%v want %v", c.host, got, c.want)
		}
	}
}
