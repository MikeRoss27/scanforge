package wpxmlrpc

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/modules/wpcore"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

const listMethodsReply = `<?xml version="1.0"?>
<methodResponse>
  <params>
    <param>
      <value>
        <array>
          <data>
            <member><value><string>system.multicall</string></value></member>
            <member><value><string>system.listMethods</string></value></member>
            <member><value><string>pingback.ping</string></value></member>
            <member><value><string>wp.getUsersBlogs</string></value></member>
          </data>
        </array>
      </value>
    </param>
  </params>
</methodResponse>`

func TestProbeXMLRPCEnabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/xmlrpc.php" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		io.WriteString(w, listMethodsReply)
	}))
	defer server.Close()

	runCtx := testRunContext(t)
	host := wpcore.FingerprintRecord{Target: server.URL, IsWordPress: true, CoreVersion: "6.4.2", FetchedAt: time.Now().UTC().Format(time.RFC3339)}
	finding := probeXMLRPC(context.Background(), server.Client(), runCtx, host)
	if !finding.Enabled {
		t.Fatal("expected XML-RPC to be detected as enabled")
	}
	if !finding.HasMulticall {
		t.Fatal("expected multicall detection")
	}
	if !finding.Pingback {
		t.Fatal("expected pingback detection")
	}
	if len(finding.Methods) != 4 {
		t.Fatalf("methods = %v, want 4 methods", finding.Methods)
	}
}

func TestProbeXMLRPCNotXMLRPC(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "plain 404-like page")
	}))
	defer server.Close()

	runCtx := testRunContext(t)
	host := wpcore.FingerprintRecord{Target: server.URL, IsWordPress: true, CoreVersion: "6.4.2", FetchedAt: time.Now().UTC().Format(time.RFC3339)}
	finding := probeXMLRPC(context.Background(), server.Client(), runCtx, host)
	if finding.Enabled {
		t.Fatalf("expected XML-RPC to be disabled, got %+v", finding)
	}
}

func TestParseMethods(t *testing.T) {
	methods := parseMethods(listMethodsReply)
	want := []string{"pingback.ping", "system.listMethods", "system.multicall", "wp.getUsersBlogs"}
	if len(methods) != len(want) {
		t.Fatalf("parseMethods returned %d methods, want %d (%v)", len(methods), len(want), methods)
	}
	for i, method := range want {
		if methods[i] != method {
			t.Fatalf("methods[%d] = %q, want %q", i, methods[i], method)
		}
	}
}

func testRunContext(t *testing.T) *modules.RunContext {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"00_meta"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	run := &storage.Run{
		RootDir:     root,
		MetaDir:     filepath.Join(root, "00_meta"),
		CommandsLog: filepath.Join(root, "00_meta", "commands.log"),
	}
	return modules.NewRunContext("example.com", "wp", false, run)
}
