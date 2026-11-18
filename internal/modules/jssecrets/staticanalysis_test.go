package jssecrets

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
)

// parseExpr parses a single expression statement and returns its expression.
func parseExpr(t *testing.T, src string) ast.Expression {
	t.Helper()
	program, err := parser.ParseFile(nil, "", src, 0)
	if err != nil {
		t.Fatalf("parse %q: %v", src, err)
	}
	stmt, ok := program.Body[0].(*ast.ExpressionStatement)
	if !ok {
		t.Fatalf("parse %q: not an expression statement", src)
	}
	return stmt.Expression
}

// byKindPattern turns findings into a lookup keyed by kind:pattern for
// assertion convenience.
func byKindPattern(findings []finding) map[string]finding {
	out := make(map[string]finding, len(findings))
	for _, f := range findings {
		out[f.Kind+":"+f.Pattern] = f
	}
	return out
}

func TestScanASTDetectsDOMSinks(t *testing.T) {
	body := strings.Join([]string{
		`eval(userInput);`,
		`var f = new Function(userInput);`,
		`document.write(location.hash);`,
		`el.innerHTML = params.q;`,
		`el.outerHTML = data;`,
		`el.insertAdjacentHTML("beforeend", userInput);`,
		`setTimeout("alert(1)", 100);`,
		`location.href = userInput;`,
	}, "\n")

	findings := scanAST("https://target.example/app.js", body)
	got := byKindPattern(findings)

	for _, key := range []string{
		"dom-sink:eval-call",
		"dom-sink:new-function-sink",
		"dom-sink:document-write",
		"dom-sink:html-assignment", // innerHTML and outerHTML on separate lines
		"dom-sink:insert-adjacent-html",
		"dom-sink:timer-with-string",
		"dom-sink:location-assignment",
	} {
		if _, ok := got[key]; !ok {
			t.Errorf("missing %s (got: %+v)", key, findings)
		}
	}

	if len(findings) != 8 {
		t.Fatalf("findings = %d, want 8 (unexpected extra detections: %+v)", len(findings), findings)
	}

	for _, f := range findings {
		if f.Snippet == "" || f.Line == 0 {
			t.Errorf("finding %s missing position info: %+v", f.Pattern, f)
		}
		if len(f.Payloads) == 0 {
			t.Errorf("finding %s has no payloads", f.Pattern)
		}
		for _, p := range f.Payloads {
			if strings.TrimSpace(p) == "" {
				t.Errorf("finding %s has an empty payload", f.Pattern)
			}
		}
	}
}

func TestScanASTDetectsNodeAndEnvUsage(t *testing.T) {
	body := strings.Join([]string{
		`const { exec } = require('child_process');`,
		`var fs = require("node:fs");`,
		`const token = process.env.API_TOKEN;`,
		`fs.readFileSync('/etc/passwd');`,
	}, "\n")

	findings := scanAST("https://target.example/app.js", body)
	got := byKindPattern(findings)

	for _, key := range []string{
		"node-sink:node-child-process-require",
		"node-sink:node-fs-require",
		"env-leak:process-env-access",
	} {
		if _, ok := got[key]; !ok {
			t.Errorf("missing %s (got: %+v)", key, findings)
		}
	}
}

func TestScanASTDetectsPrototypePollution(t *testing.T) {
	body := strings.Join([]string{
		`obj.__proto__ = payload;`,
		`Object.defineProperty(obj, "__proto__", {value: payload});`,
		`Reflect.set(obj, "__proto__", payload);`,
		`var evil = {"__proto__": {"isAdmin": true}};`,
		`obj.constructor.prototype.polluted = true;`,
	}, "\n")

	findings := scanAST("https://target.example/app.js", body)
	got := byKindPattern(findings)

	for _, key := range []string{
		"proto-pollution:proto-pollution-assignment",
		"proto-pollution:proto-pollution-define-property",
		"proto-pollution:proto-pollution-reflect-set",
		"proto-pollution:proto-pollution-object-literal",
		"proto-pollution:constructor-prototype-assignment",
	} {
		if _, ok := got[key]; !ok {
			t.Errorf("missing %s (got: %+v)", key, findings)
		}
	}
}

func TestScanASTSkipsFrameworkPatterns(t *testing.T) {
	body := strings.Join([]string{
		`var globalThisProxy = Function("return this")();`,
		`var g = new Function("return this")();`,
		`var safe = Object.assign({}, userInput);`,
		`var map = {"__proto__": null};`,
		`var poly = {"__proto__": []};`,
		`location.href = "/search";`,
		`window.location = "/";`,
	}, "\n")

	if findings := scanAST("https://target.example/app.js", body); len(findings) != 0 {
		t.Fatalf("expected no findings for framework patterns, got %+v", findings)
	}
}

func TestScanASTDetectsPostMessageIssues(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			"wildcard origin",
			`window.parent.postMessage(userData, "*");`,
			"postmessage:postmessage-wildcard",
		},
		{
			"listener without origin check",
			`window.addEventListener("message", function(e) { doSomething(e.data); });`,
			"postmessage:message-listener-no-origin-check",
		},
		{
			"safe explicit origin",
			`window.parent.postMessage(userData, "https://app.example.com");`,
			"",
		},
		{
			// The HTML standard defaults targetOrigin to "/" (same origin),
			// so an absent argument is not a wildcard.
			"missing target origin is same-origin",
			`parent.postMessage(userData);`,
			"",
		},
		{
			// A handler imported from another module cannot be inspected.
			"unresolved named listener",
			`window.addEventListener("message", importedHandler, false);`,
			"",
		},
		{
			"safe listener with origin check",
			`window.addEventListener("message", function(e) { if (e.origin !== "https://app.example.com") return; go(e.data); });`,
			"",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scanAST("https://target.example/app.js", tc.body)
			got := byKindPattern(findings)
			if tc.want == "" {
				if len(findings) != 0 {
					t.Fatalf("expected no findings, got %+v", findings)
				}
				return
			}
			if _, ok := got[tc.want]; !ok {
				t.Fatalf("missing %s (got: %+v)", tc.want, findings)
			}
		})
	}
}

func TestScanASTKeepsLibraryCandidatesForReview(t *testing.T) {
	body := strings.Join([]string{
		// core-js Function.prototype.bind polyfill.
		`var bind = Function("binder", "return function (" + args + "){ return binder.apply(this,arguments); }");`,
		// vm-browserify runInThisContext/runInNewContext shim.
		`Script.prototype.runInThisContext = function () { return eval(this.code); };`,
		`Script.prototype.runInNewContext = function (e) { return this.runInContext(e); };`,
		// core-js setImmediate polyfill: postMessage to itself, no origin.
		`var shared = "__core-js_shared__";`,
		`var dispatchImmediate = function (t) { run(t.data); };`,
		`i.addEventListener("message", dispatchImmediate, false);`,
		`var channel = new MessageChannel(); channel.port2.postMessage(null);`,
	}, "\n")

	findings := scanAST("https://target.example/chunk.js", body)
	if len(findings) != 3 {
		t.Fatalf("expected Function, eval and message listener candidates, got %+v", findings)
	}
	for _, f := range findings {
		if f.Severity != "medium" {
			t.Errorf("library candidate should remain for review: %+v", f)
		}
	}
}

func TestScanASTSkipsStaticMarkup(t *testing.T) {
	body := strings.Join([]string{
		`el.innerHTML = "<b>hello</b>";`,
		"el.outerHTML = `<span>hi</span>`;",
		`frame.srcdoc = "<p>static</p>";`,
		`location.href = "/search";`,
	}, "\n")

	if findings := scanAST("https://target.example/app.js", body); len(findings) != 0 {
		t.Fatalf("expected no findings for static markup, got %+v", findings)
	}
}

func TestScanASTSeverityDependsOnUserControlledSource(t *testing.T) {
	body := strings.Join([]string{
		`el.innerHTML = location.hash;`,
		`other.innerHTML = data;`,
		`sub.__proto__ = superClass;`,
		`target.__proto__ = JSON.parse(location.hash);`,
		`box.innerHTML = e.data;`,
	}, "\n")

	severityBySnippet := make(map[string]string)
	for _, f := range scanAST("https://target.example/app.js", body) {
		severityBySnippet[strings.TrimSuffix(f.Snippet, ";")] = f.Severity
	}

	cases := map[string]string{
		`el.innerHTML = location.hash;`:                 "high",
		`other.innerHTML = data;`:                       "medium",
		`sub.__proto__ = superClass;`:                   "low",
		`target.__proto__ = JSON.parse(location.hash);`: "high",
		`box.innerHTML = e.data;`:                       "high",
	}
	for snippet, want := range cases {
		if got := severityBySnippet[strings.TrimSuffix(snippet, ";")]; got != want {
			t.Errorf("severity for %q = %q, want %q (findings: %+v)", snippet, got, want, severityBySnippet)
		}
	}
}

func TestScanASTSkipsBenignCode(t *testing.T) {
	body := strings.Join([]string{
		`const name = "eval";`,
		`el.textContent = userInput;`,
		`Object.assign(target, {a: 1});`,
		`window.addEventListener("click", onClick);`,
		`const orig = e.origin;`,
	}, "\n")

	if findings := scanAST("https://target.example/app.js", body); len(findings) != 0 {
		t.Fatalf("expected no findings for benign code, got %+v", findings)
	}
}

func TestScanASTToleratesUnparsableInput(t *testing.T) {
	if findings := scanAST("https://target.example/app.js", "<html><body>not javascript</body>"); findings != nil {
		t.Fatalf("unparsable input should yield no findings, got %+v", findings)
	}
}

func TestScanASTCarriesPayloadsForEachPattern(t *testing.T) {
	body := `eval(a); document.write(b); obj.__proto__ = p;`
	findings := scanAST("https://target.example/app.js", body)
	if len(findings) != 3 {
		t.Fatalf("findings = %+v, want 3", findings)
	}
	keys := make([]string, 0, len(payloadLibrary))
	for key := range payloadLibrary {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if len(payloadLibrary[key]) == 0 {
			t.Errorf("payload library entry %q is empty", key)
		}
	}
}

func TestCollectPayloadsDeduplicates(t *testing.T) {
	findings := []finding{
		{Payloads: []string{"a", "b"}},
		{Payloads: []string{"b", "c"}},
	}
	got := collectPayloads(findings)
	sort.Strings(got)
	if want := []string{"a", "b", "c"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("collectPayloads = %v, want %v", got, want)
	}
}

func TestMemberName(t *testing.T) {
	cases := map[string]string{
		`eval`:                    "eval",
		`document.write`:          "document.write",
		`window["eval"]`:          "window.eval",
		`location.href`:           "location.href",
		`document.body.innerHTML`: "document.body.innerHTML",
		`process.env.TOKEN`:       "process.env.TOKEN",
		`Reflect.set`:             "Reflect.set",
		`Object.assign`:           "Object.assign",
		`parent.postMessage`:      "parent.postMessage",
		`window.addEventListener`: "window.addEventListener",
		`require`:                 "require",
	}
	for src, want := range cases {
		expr := parseExpr(t, src)
		if got := memberName(expr); got != want {
			t.Errorf("memberName(%q) = %q, want %q", src, got, want)
		}
	}
}

func TestMemberNameUnresolvable(t *testing.T) {
	expr := parseExpr(t, `obj[key]`)
	if got := memberName(expr); got != "" {
		t.Errorf("memberName(obj[key]) = %q, want empty (dynamic member)", got)
	}
}

func TestScanASTLibraryMarkersDoNotHideApplicationSinks(t *testing.T) {
	body := `var shared="__core-js_shared__"; var runInThisContext, runInNewContext;
	function execute() { eval(this.code); }
	Function("binder", location.hash + "binder.apply(this,arguments)");
	window.addEventListener("message", function(e) { execute(e.data); });`
	got := byKindPattern(scanAST("https://target.example/_next/static/chunks/app.js", body))
	for pattern, severity := range map[string]string{
		"dom-sink:eval-call":                           "medium",
		"dom-sink:function-sink":                       "high",
		"postmessage:message-listener-no-origin-check": "medium",
	} {
		if got[pattern].Severity != severity {
			t.Errorf("%s = %+v, want %s", pattern, got[pattern], severity)
		}
	}
}
