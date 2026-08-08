// Static analysis of fetched JavaScript: parses each file with a real JS AST
// and flags dangerous patterns that regexes cannot see, such as DOM XSS sinks,
// server-side (Node) APIs bundled into a page, prototype pollution vectors and
// unvalidated postMessage usage. Findings are paired with ready-to-use PoC
// payloads for manual verification.

package jssecrets

import (
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
)

const (
	kindDOMSink        = "dom-sink"
	kindNodeSink       = "node-sink"
	kindProtoPollution = "proto-pollution"
	kindPostMessage    = "postmessage"
	kindEnvLeak        = "env-leak"
)

// snippetMax caps the code fragment attached to a finding so minified
// one-line bundles do not blow up the output.
const snippetMax = 160

// analyzer walks one parsed program and collects dangerous-pattern findings.
type analyzer struct {
	program  *ast.Program
	source   string
	target   string
	findings []finding
	seen     map[string]struct{}
}

func scanAST(target, source string) []finding {
	program, err := parser.ParseFile(nil, "", source, 0)
	if err != nil || len(program.Body) == 0 {
		// Unparsable bundles (HTML-ish files, JSONP payloads, truncated
		// responses) fall back to the regex scan only.
		return nil
	}
	an := &analyzer{
		program: program,
		source:  source,
		target:  target,
		seen:    make(map[string]struct{}),
	}
	for _, stmt := range program.Body {
		an.walkStmt(stmt)
	}
	return an.findings
}

// report records a finding unless the exact same pattern+snippet already
// appeared in this file (minified bundles repeat code paths constantly).
func (an *analyzer) report(kind, pattern, severity string, node ast.Node, payloads []string) {
	snippet := an.snippet(node)
	key := pattern + "\x00" + snippet
	if _, ok := an.seen[key]; ok {
		return
	}
	an.seen[key] = struct{}{}
	an.findings = append(an.findings, finding{
		URL:      an.target,
		Kind:     kind,
		Pattern:  pattern,
		Severity: severity,
		Match:    snippet,
		Line:     an.line(node),
		Snippet:  snippet,
		Payloads: payloads,
	})
}

// snippet returns the compacted source text covered by node. goja Idx values
// are base-encoded positions, so the file's base must be subtracted to get
// plain byte offsets into the source.
func (an *analyzer) snippet(node ast.Node) string {
	base := an.program.File.Base()
	start := int(node.Idx0()) - base
	end := int(node.Idx1()) - base
	if start < 0 || end > len(an.source) || start >= end {
		return ""
	}
	raw := an.source[start:end]
	raw = strings.Join(strings.Fields(raw), " ")
	if len(raw) > snippetMax {
		raw = raw[:snippetMax] + "…"
	}
	return raw
}

func (an *analyzer) line(node ast.Node) int {
	return an.program.File.Position(int(node.Idx0()) - an.program.File.Base()).Line
}

// ---------------------------------------------------------------------------
// Recursive AST walker
// ---------------------------------------------------------------------------

func (an *analyzer) walkStmt(s ast.Statement) {
	switch n := s.(type) {
	case *ast.BlockStatement:
		for _, stmt := range n.List {
			an.walkStmt(stmt)
		}
	case *ast.ExpressionStatement:
		an.walkExpr(n.Expression)
	case *ast.VariableStatement:
		for _, binding := range n.List {
			an.walkBinding(binding)
		}
	case *ast.LexicalDeclaration:
		for _, binding := range n.List {
			an.walkBinding(binding)
		}
	case *ast.IfStatement:
		an.walkExpr(n.Test)
		an.walkStmt(n.Consequent)
		if n.Alternate != nil {
			an.walkStmt(n.Alternate)
		}
	case *ast.ForStatement:
		an.walkForInitializer(n.Initializer)
		if n.Test != nil {
			an.walkExpr(n.Test)
		}
		if n.Update != nil {
			an.walkExpr(n.Update)
		}
		an.walkStmt(n.Body)
	case *ast.ForInStatement:
		an.walkForInto(n.Into)
		an.walkExpr(n.Source)
		an.walkStmt(n.Body)
	case *ast.ForOfStatement:
		an.walkForInto(n.Into)
		an.walkExpr(n.Source)
		an.walkStmt(n.Body)
	case *ast.WhileStatement:
		an.walkExpr(n.Test)
		an.walkStmt(n.Body)
	case *ast.DoWhileStatement:
		an.walkExpr(n.Test)
		an.walkStmt(n.Body)
	case *ast.ReturnStatement:
		if n.Argument != nil {
			an.walkExpr(n.Argument)
		}
	case *ast.ThrowStatement:
		if n.Argument != nil {
			an.walkExpr(n.Argument)
		}
	case *ast.TryStatement:
		an.walkStmt(n.Body)
		if n.Catch != nil {
			an.walkStmt(n.Catch.Body)
		}
		if n.Finally != nil {
			an.walkStmt(n.Finally)
		}
	case *ast.SwitchStatement:
		an.walkExpr(n.Discriminant)
		for _, cs := range n.Body {
			if cs.Test != nil {
				an.walkExpr(cs.Test)
			}
			for _, stmt := range cs.Consequent {
				an.walkStmt(stmt)
			}
		}
	case *ast.FunctionDeclaration:
		an.walkFunction(n.Function)
	case *ast.ClassDeclaration:
		an.walkClass(n.Class)
	case *ast.WithStatement:
		an.walkExpr(n.Object)
		an.walkStmt(n.Body)
	case *ast.LabelledStatement:
		an.walkStmt(n.Statement)
	}
	// BranchStatement, BadStatement, DebuggerStatement, EmptyStatement: nothing.
}

func (an *analyzer) walkBinding(b *ast.Binding) {
	if b == nil {
		return
	}
	an.walkExpr(b.Target)
	if b.Initializer != nil {
		an.walkExpr(b.Initializer)
	}
}

func (an *analyzer) walkForInitializer(init ast.ForLoopInitializer) {
	switch n := init.(type) {
	case *ast.ForLoopInitializerExpression:
		an.walkExpr(n.Expression)
	case *ast.ForLoopInitializerVarDeclList:
		for _, binding := range n.List {
			an.walkBinding(binding)
		}
	case *ast.ForLoopInitializerLexicalDecl:
		for _, binding := range n.LexicalDeclaration.List {
			an.walkBinding(binding)
		}
	}
}

func (an *analyzer) walkForInto(into ast.ForInto) {
	switch n := into.(type) {
	case *ast.ForIntoVar:
		an.walkBinding(n.Binding)
	case *ast.ForDeclaration:
		an.walkExpr(n.Target)
	case *ast.ForIntoExpression:
		an.walkExpr(n.Expression)
	}
}

func (an *analyzer) walkExpr(e ast.Expression) {
	if e == nil {
		return
	}
	switch n := e.(type) {
	case *ast.CallExpression:
		an.checkCall(n)
		an.walkExpr(n.Callee)
		for _, arg := range n.ArgumentList {
			an.walkExpr(arg)
		}
	case *ast.NewExpression:
		an.checkNew(n)
		an.walkExpr(n.Callee)
		for _, arg := range n.ArgumentList {
			an.walkExpr(arg)
		}
	case *ast.AssignExpression:
		an.checkAssign(n)
		an.walkExpr(n.Left)
		an.walkExpr(n.Right)
	case *ast.DotExpression:
		an.checkEnvAccess(n)
		an.walkExpr(n.Left)
	case *ast.BracketExpression:
		an.walkExpr(n.Left)
		an.walkExpr(n.Member)
	case *ast.ObjectLiteral:
		for _, prop := range n.Value {
			an.walkProperty(prop)
		}
	case *ast.ObjectPattern:
		for _, prop := range n.Properties {
			an.walkProperty(prop)
		}
		if n.Rest != nil {
			an.walkExpr(n.Rest)
		}
	case *ast.ArrayLiteral:
		for _, el := range n.Value {
			an.walkExpr(el)
		}
	case *ast.ArrayPattern:
		for _, el := range n.Elements {
			an.walkExpr(el)
		}
		if n.Rest != nil {
			an.walkExpr(n.Rest)
		}
	case *ast.BinaryExpression:
		an.walkExpr(n.Left)
		an.walkExpr(n.Right)
	case *ast.UnaryExpression:
		an.walkExpr(n.Operand)
	case *ast.ConditionalExpression:
		an.walkExpr(n.Test)
		an.walkExpr(n.Consequent)
		an.walkExpr(n.Alternate)
	case *ast.SequenceExpression:
		for _, ex := range n.Sequence {
			an.walkExpr(ex)
		}
	case *ast.FunctionLiteral:
		an.walkFunction(n)
	case *ast.ArrowFunctionLiteral:
		an.walkArrow(n)
	case *ast.ClassLiteral:
		an.walkClass(n)
	case *ast.AwaitExpression:
		an.walkExpr(n.Argument)
	case *ast.YieldExpression:
		if n.Argument != nil {
			an.walkExpr(n.Argument)
		}
	case *ast.TemplateLiteral:
		if n.Tag != nil {
			an.walkExpr(n.Tag)
		}
		for _, exp := range n.Expressions {
			an.walkExpr(exp)
		}
	case *ast.OptionalChain:
		an.walkExpr(n.Expression)
	case *ast.Optional:
		an.walkExpr(n.Expression)
	case *ast.SpreadElement:
		an.walkExpr(n.Expression)
	}
	// Literals and identifiers: nothing to inspect further.
}

func (an *analyzer) walkProperty(p ast.Property) {
	switch n := p.(type) {
	case *ast.PropertyKeyed:
		an.checkObjectKey(n)
		an.walkExpr(n.Key)
		an.walkExpr(n.Value)
	case *ast.PropertyShort:
		if n.Initializer != nil {
			an.walkExpr(n.Initializer)
		}
	case *ast.SpreadElement:
		an.walkExpr(n.Expression)
	}
}

func (an *analyzer) walkFunction(fn *ast.FunctionLiteral) {
	if fn.Body != nil {
		for _, stmt := range fn.Body.List {
			an.walkStmt(stmt)
		}
	}
}

func (an *analyzer) walkArrow(fn *ast.ArrowFunctionLiteral) {
	switch body := fn.Body.(type) {
	case *ast.BlockStatement:
		for _, stmt := range body.List {
			an.walkStmt(stmt)
		}
	case *ast.ExpressionBody:
		an.walkExpr(body.Expression)
	}
}

func (an *analyzer) walkClass(cls *ast.ClassLiteral) {
	if cls.SuperClass != nil {
		an.walkExpr(cls.SuperClass)
	}
	for _, el := range cls.Body {
		switch n := el.(type) {
		case *ast.FieldDefinition:
			if n.Key != nil {
				an.walkExpr(n.Key)
			}
			if n.Initializer != nil {
				an.walkExpr(n.Initializer)
			}
		case *ast.MethodDefinition:
			if n.Key != nil {
				an.walkExpr(n.Key)
			}
			if n.Body != nil {
				an.walkFunction(n.Body)
			}
		case *ast.ClassStaticBlock:
			if n.Block != nil {
				for _, stmt := range n.Block.List {
					an.walkStmt(stmt)
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Pattern checks
// ---------------------------------------------------------------------------

// checkCall inspects a call expression for known dangerous targets.
func (an *analyzer) checkCall(n *ast.CallExpression) {
	name := memberName(n.Callee)
	last := lastSegment(name)
	switch {
	case last == "eval":
		an.report(kindDOMSink, "eval-call", "high", n, payloadLibrary["eval"])
	case last == "Function":
		if hasDynamicArgument(n.ArgumentList) {
			// Function("return this") is the standard global-this polyfill
			// emitted by every bundler; only dynamic code strings matter.
			an.report(kindDOMSink, "function-sink", "high", n, payloadLibrary["function"])
		}
	case last == "write" || last == "writeln":
		if strings.HasPrefix(name, "document.") {
			an.report(kindDOMSink, "document-write", "high", n, payloadLibrary["document-write"])
		}
	case last == "insertAdjacentHTML":
		an.report(kindDOMSink, "insert-adjacent-html", "medium", n, payloadLibrary["html"])
	case last == "setTimeout" || last == "setInterval":
		if len(n.ArgumentList) > 0 {
			if _, ok := n.ArgumentList[0].(*ast.StringLiteral); ok {
				an.report(kindDOMSink, "timer-with-string", "medium", n, payloadLibrary["timer"])
			}
		}
	case last == "postMessage":
		an.checkPostMessage(n)
	case last == "addEventListener":
		an.checkMessageListener(n)
	case last == "require":
		an.checkRequire(n)
	case last == "defineProperty":
		if name == "Object.defineProperty" {
			an.checkDefineProperty(n)
		}
	case last == "set" && name == "Reflect.set":
		if len(n.ArgumentList) >= 2 {
			if lit, ok := n.ArgumentList[1].(*ast.StringLiteral); ok && lit.Value.String() == "__proto__" {
				an.report(kindProtoPollution, "proto-pollution-reflect-set", "high", n, payloadLibrary["proto-pollution"])
			}
		}
	}
}

// hasDynamicArgument reports whether any argument is not a string literal:
// literal-only calls such as Function("return this") are framework polyfills.
func hasDynamicArgument(args []ast.Expression) bool {
	for _, arg := range args {
		if _, ok := arg.(*ast.StringLiteral); !ok {
			return true
		}
	}
	return false
}

func (an *analyzer) checkNew(n *ast.NewExpression) {
	if lastSegment(memberName(n.Callee)) == "Function" && hasDynamicArgument(n.ArgumentList) {
		an.report(kindDOMSink, "new-function-sink", "high", n, payloadLibrary["function"])
	}
}

// checkAssign inspects LHS targets of assignments.
func (an *analyzer) checkAssign(n *ast.AssignExpression) {
	chain := memberName(n.Left)
	switch {
	case hasSuffix(chain, "innerHTML"), hasSuffix(chain, "outerHTML"):
		an.report(kindDOMSink, "html-assignment", "high", n, payloadLibrary["html"])
	case hasSuffix(chain, "srcdoc"):
		an.report(kindDOMSink, "srcdoc-assignment", "medium", n, payloadLibrary["html"])
	case strings.Contains(chain, ".__proto__"):
		// Matches both "obj.__proto__ = v" and "obj.__proto__.x = v".
		an.report(kindProtoPollution, "proto-pollution-assignment", "high", n, payloadLibrary["proto-pollution"])
	case strings.Contains(chain, ".constructor.prototype"):
		an.report(kindProtoPollution, "constructor-prototype-assignment", "high", n, payloadLibrary["proto-pollution"])
	case chain == "location" || hasSuffix(chain, "location.href"):
		// Static navigations (location.href = "/search") are fine; only
		// dynamically computed destinations are worth testing.
		if _, literal := n.Right.(*ast.StringLiteral); !literal {
			an.report(kindDOMSink, "location-assignment", "medium", n, payloadLibrary["location"])
		}
	}
}

// checkPostMessage flags postMessage calls with a wildcard or no targetOrigin.
func (an *analyzer) checkPostMessage(n *ast.CallExpression) {
	switch {
	case len(n.ArgumentList) < 2:
		an.report(kindPostMessage, "postmessage-missing-origin", "medium", n, payloadLibrary["postmessage"])
	case len(n.ArgumentList) >= 2:
		if lit, ok := n.ArgumentList[1].(*ast.StringLiteral); ok && lit.Value.String() == "*" {
			an.report(kindPostMessage, "postmessage-wildcard", "medium", n, payloadLibrary["postmessage"])
		}
	}
}

// checkMessageListener flags "message" listeners that never inspect event.origin.
func (an *analyzer) checkMessageListener(n *ast.CallExpression) {
	if len(n.ArgumentList) < 2 {
		return
	}
	ev, ok := n.ArgumentList[0].(*ast.StringLiteral)
	if !ok || ev.Value.String() != "message" {
		return
	}
	if !checksOrigin(n.ArgumentList[1]) {
		an.report(kindPostMessage, "message-listener-no-origin-check", "medium", n, payloadLibrary["postmessage"])
	}
}

// checkRequire flags require() of modules that only make sense server-side.
func (an *analyzer) checkRequire(n *ast.CallExpression) {
	if len(n.ArgumentList) != 1 {
		return
	}
	lit, ok := n.ArgumentList[0].(*ast.StringLiteral)
	if !ok {
		return
	}
	switch strings.TrimPrefix(lit.Value.String(), "node:") {
	case "child_process":
		an.report(kindNodeSink, "node-child-process-require", "high", n, payloadLibrary["child-process"])
	case "fs":
		an.report(kindNodeSink, "node-fs-require", "medium", n, payloadLibrary["fs"])
	}
}

// checkDefineProperty flags Object.defineProperty(target, "__proto__", ...).
func (an *analyzer) checkDefineProperty(n *ast.CallExpression) {
	if len(n.ArgumentList) < 2 {
		return
	}
	if lit, ok := n.ArgumentList[1].(*ast.StringLiteral); ok && lit.Value.String() == "__proto__" {
		an.report(kindProtoPollution, "proto-pollution-define-property", "high", n, payloadLibrary["proto-pollution"])
	}
}

// checkObjectKey flags __proto__ keys in object literals, except the standard
// mitigation patterns "{__proto__: null}" (null-prototype map) and
// "{__proto__: []}" (engine quirk used by polyfills to reset the prototype).
func (an *analyzer) checkObjectKey(p *ast.PropertyKeyed) {
	key := ""
	if lit, ok := p.Key.(*ast.StringLiteral); ok {
		key = lit.Value.String()
	} else if id, ok := p.Key.(*ast.Identifier); ok {
		key = id.Name.String()
	}
	if key != "__proto__" {
		return
	}
	switch value := p.Value.(type) {
	case *ast.NullLiteral:
		return
	case *ast.ArrayLiteral:
		if len(value.Value) == 0 {
			return
		}
	}
	an.report(kindProtoPollution, "proto-pollution-object-literal", "high", p, payloadLibrary["proto-pollution"])
}

// checkEnvAccess flags process.env reads, which leak server-side configuration
// when Node source is bundled into a page.
func (an *analyzer) checkEnvAccess(n *ast.DotExpression) {
	if n.Identifier.Name.String() != "env" {
		return
	}
	if lastSegment(memberName(n.Left)) == "process" {
		an.report(kindEnvLeak, "process-env-access", "low", n, payloadLibrary["env"])
	}
}

// ---------------------------------------------------------------------------
// Expression helpers
// ---------------------------------------------------------------------------

// memberName resolves an expression to a dotted property path ("document.write",
// "window["eval"]"), or "" when it is not statically resolvable.
func memberName(e ast.Expression) string {
	switch n := e.(type) {
	case *ast.Identifier:
		return n.Name.String()
	case *ast.DotExpression:
		left := memberName(n.Left)
		if left == "" {
			return ""
		}
		return left + "." + n.Identifier.Name.String()
	case *ast.BracketExpression:
		lit, ok := n.Member.(*ast.StringLiteral)
		if !ok {
			return ""
		}
		left := memberName(n.Left)
		if left == "" {
			return ""
		}
		return left + "." + lit.Value.String()
	}
	return ""
}

func lastSegment(name string) string {
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		return name[i+1:]
	}
	return name
}

func hasSuffix(chain, suffix string) bool {
	return chain == suffix || strings.HasSuffix(chain, "."+suffix)
}

// checksOrigin reports whether the given callback (function literal or arrow
// function) references event.origin anywhere in its body.
func checksOrigin(handler ast.Expression) bool {
	found := false
	var walkStmt func(s ast.Statement)
	var walkExpr func(e ast.Expression)
	var walkBinding func(b *ast.Binding)

	checkName := func(name string) {
		if name == "origin" {
			found = true
		}
	}

	walkStmt = func(s ast.Statement) {
		if s == nil || found {
			return
		}
		switch n := s.(type) {
		case *ast.BlockStatement:
			for _, stmt := range n.List {
				walkStmt(stmt)
			}
		case *ast.ExpressionStatement:
			walkExpr(n.Expression)
		case *ast.VariableStatement:
			for _, binding := range n.List {
				walkBinding(binding)
			}
		case *ast.LexicalDeclaration:
			for _, binding := range n.List {
				walkBinding(binding)
			}
		case *ast.IfStatement:
			walkExpr(n.Test)
			walkStmt(n.Consequent)
			if n.Alternate != nil {
				walkStmt(n.Alternate)
			}
		case *ast.ReturnStatement:
			if n.Argument != nil {
				walkExpr(n.Argument)
			}
		case *ast.WhileStatement:
			walkExpr(n.Test)
			walkStmt(n.Body)
		case *ast.ForStatement:
			walkStmt(n.Body)
		case *ast.ForOfStatement:
			walkStmt(n.Body)
		case *ast.TryStatement:
			walkStmt(n.Body)
			if n.Catch != nil {
				walkStmt(n.Catch.Body)
			}
			if n.Finally != nil {
				walkStmt(n.Finally)
			}
		}
	}

	walkBinding = func(b *ast.Binding) {
		if b == nil || found {
			return
		}
		if b.Initializer != nil {
			walkExpr(b.Initializer)
		}
	}

	walkExpr = func(e ast.Expression) {
		if e == nil || found {
			return
		}
		switch n := e.(type) {
		case *ast.DotExpression:
			if n.Identifier.Name.String() == "origin" {
				found = true
				return
			}
			walkExpr(n.Left)
		case *ast.BracketExpression:
			if lit, ok := n.Member.(*ast.StringLiteral); ok && lit.Value.String() == "origin" {
				found = true
				return
			}
			walkExpr(n.Left)
			walkExpr(n.Member)
		case *ast.CallExpression:
			walkExpr(n.Callee)
			for _, arg := range n.ArgumentList {
				walkExpr(arg)
			}
		case *ast.NewExpression:
			walkExpr(n.Callee)
			for _, arg := range n.ArgumentList {
				walkExpr(arg)
			}
		case *ast.AssignExpression:
			walkExpr(n.Left)
			walkExpr(n.Right)
		case *ast.BinaryExpression:
			walkExpr(n.Left)
			walkExpr(n.Right)
		case *ast.UnaryExpression:
			walkExpr(n.Operand)
		case *ast.ConditionalExpression:
			walkExpr(n.Test)
			walkExpr(n.Consequent)
			walkExpr(n.Alternate)
		case *ast.FunctionLiteral:
			walkStmt(n.Body)
		case *ast.ArrowFunctionLiteral:
			switch body := n.Body.(type) {
			case *ast.BlockStatement:
				walkStmt(body)
			case *ast.ExpressionBody:
				walkExpr(body.Expression)
			}
		case *ast.ObjectLiteral:
			for _, prop := range n.Value {
				if pk, ok := prop.(*ast.PropertyKeyed); ok {
					walkExpr(pk.Value)
				}
			}
		case *ast.Identifier:
			checkName(n.Name.String())
		}
	}

	walkExpr(handler)
	return found
}
