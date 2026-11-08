// Package dart analyzes Dart and Flutter source with tree-sitter. It parses
// files and never runs them, pub, or build_runner.
package dart

import (
	"context"
	"path"
	"strings"

	ts "github.com/tree-sitter/go-tree-sitter"

	"github.com/roburns/urfluency-cli/analysis"
	"github.com/roburns/urfluency-cli/parsing"
)

func init() { analysis.Register(Analyzer{}) }

// Analyzer implements analysis.Analyzer for Dart.
type Analyzer struct{}

func (Analyzer) Language() string     { return "dart" }
func (Analyzer) Extensions() []string { return []string{".dart"} }

// generatedSuffixes are the outputs of build_runner generators such as
// json_serializable, freezed, auto_route, injectable, and mockito.
var generatedSuffixes = []string{".g.dart", ".freezed.dart", ".gr.dart", ".config.dart", ".mocks.dart"}

// SkipPath excludes build output, the pub tool directory, and generated files.
func (Analyzer) SkipPath(p string) bool {
	if parsing.InDir(p, "build", ".dart_tool") {
		return true
	}
	base := path.Base(p)
	for _, s := range generatedSuffixes {
		if strings.HasSuffix(base, s) {
			return true
		}
	}
	return false
}

// Skip also excludes files that carry the generator header.
func (a Analyzer) Skip(f analysis.File) bool {
	if a.SkipPath(f.Path) {
		return true
	}
	return parsing.GeneratedHeader(f.Content)
}

// Complexity is the cognitive complexity syntax for the Dart grammar. Function
// signatures and bodies are siblings in this grammar, so the body is the
// function node. An else-if is an if_statement directly inside another, so the
// inner if is not counted twice. The grammar has no else node, so else
// branches are counted by their anonymous else token, and it splits && and ||
// into separate node kinds without an operator field, which LogicalKinds maps
// to their operators so each sequence counts once.
var Complexity = parsing.ComplexitySyntax{
	Functions: kinds("function_body", "function_expression"),
	Structures: kinds("if_statement", "for_statement", "while_statement", "do_statement", "switch_statement",
		"switch_expression", "catch_clause", "conditional_expression", "if_element", "for_element"),
	ElseToken:    "else",
	LogicalKinds: map[string]string{"logical_and_expression": "&&", "logical_or_expression": "||"},
	LogicalOps:   kinds("&&", "||"),
	Jumps:        kinds("break_statement", "continue_statement"),
	Label:        "identifier",
}

func kinds(ks ...string) map[string]bool {
	m := make(map[string]bool, len(ks))
	for _, k := range ks {
		m[k] = true
	}
	return m
}

// Analyze applies every Dart rule to each file.
func (Analyzer) Analyze(ctx context.Context, files []analysis.File) ([]analysis.Finding, error) {
	var findings []analysis.Finding
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		tree, err := parsing.Parse(parsing.Dart, f.Content)
		if err != nil {
			continue
		}
		c := checker{tree: tree, path: f.Path, isTest: analysis.IsTestPath(f.Path), frameworks: importedFrameworks(tree)}
		parsing.Walk(tree.Root(), c.visit)
		parsing.Walk(tree.Root(), c.visitIdioms)
		if !c.isTest {
			for _, fn := range parsing.Cognitive(tree, Complexity) {
				c.findings = append(c.findings, analysis.EvidenceOf(f.Path, fn.Line, fn.Complexity)...)
				if fn.Complexity > parsing.CognitiveThreshold {
					c.findings = append(c.findings, analysis.Finding{Rule: "clean.cognitive-complexity", Path: f.Path, Line: fn.Line})
				}
			}
		}
		tree.Close()
		findings = append(findings, c.findings...)
	}
	return findings, nil
}

type checker struct {
	tree       *parsing.Tree
	path       string
	isTest     bool
	frameworks map[string]bool
	findings   []analysis.Finding
	primaries  map[uintptr]*ts.Node // selector to the primary expression of its chain
}

func (c *checker) report(rule string, n *ts.Node) {
	c.findings = append(c.findings, analysis.Finding{Rule: rule, Path: c.path, Line: parsing.Line(n)})
}

func (c *checker) visit(n *ts.Node) bool {
	switch n.Kind() {
	case "type_identifier":
		// Map<String, dynamic> is the standard JSON shape, so type arguments are allowed.
		if !c.isTest && c.tree.Text(n) == "dynamic" && n.Parent() != nil && n.Parent().Kind() != "type_arguments" {
			c.report("dart.dynamic-type", n)
		}
	case "selector":
		if !c.isTest && n.ChildCount() == 1 && n.Child(0).Kind() == "!" {
			c.report("dart.null-assertion", n)
		}
		if primary, callee := c.call(n); primary != nil {
			c.checkCall(primary, callee, n)
		}
	case "try_statement":
		c.checkEmptyCatch(n)
	case "function_body", "function_expression_body":
		if c.frameworks["flutter"] && parsing.HasToken(n, "async") {
			c.checkSetStateAfterAwait(n)
		}
	case "class_definition":
		if c.frameworks["flutter"] {
			c.checkMissingDispose(n)
		}
	}
	return true
}

func (c *checker) checkCall(primary *ts.Node, callee string, sel *ts.Node) {
	switch callee {
	case "print":
		if c.isLibraryCode() {
			c.report("dart.print-in-library", primary)
		}
	case "Uri.parse", "Uri.tryParse":
		if !c.isTest && insecureURL(c.firstStringArgument(sel)) {
			c.report("dart.http-url-literal", primary)
		}
	}
}

// isLibraryCode reports whether the file is package code under lib/, where
// print bypasses logging, rather than an entry point, script, or test.
func (c *checker) isLibraryCode() bool {
	return !c.isTest && parsing.InDir(c.path, "lib") && path.Base(c.path) != "main.dart"
}

// selectorKinds follow a primary expression in this grammar, which keeps calls
// and member accesses flat: print(x) is an identifier then a selector.
var selectorKinds = kinds("selector", "unconditional_assignable_selector", "conditional_assignable_selector")

// call returns, for a selector that applies arguments, the primary expression
// that starts the chain and the callee text, such as "Uri.parse".
func (c *checker) call(sel *ts.Node) (*ts.Node, string) {
	if !hasChild(sel, "argument_part") {
		return nil, ""
	}
	primary := c.primaryOf(sel)
	if primary == nil {
		return nil, ""
	}
	return primary, strings.TrimSpace(string(c.tree.Source[primary.StartByte():sel.StartByte()]))
}

// primaryOf returns the primary expression before sel's run of selectors.
// PrevNamedSibling scans from the parent's first child on every call, so
// walking back from each selector of a long chain was quadratic; instead the
// parent's children are scanned once and every selector's primary recorded.
func (c *checker) primaryOf(sel *ts.Node) *ts.Node {
	if p, ok := c.primaries[sel.Id()]; ok {
		return p
	}
	if c.primaries == nil {
		c.primaries = map[uintptr]*ts.Node{}
	}
	parent := sel.Parent()
	if parent == nil {
		return nil
	}
	var primary *ts.Node
	for _, child := range parsing.NamedChildren(parent) {
		if selectorKinds[child.Kind()] {
			c.primaries[child.Id()] = primary
		} else {
			primary = child
		}
	}
	return c.primaries[sel.Id()]
}

func hasChild(n *ts.Node, kind string) bool {
	for _, child := range parsing.NamedChildren(n) {
		if child.Kind() == kind {
			return true
		}
	}
	return false
}

// firstStringArgument returns the text of a call's only argument when it is a
// string literal, or "".
func (c *checker) firstStringArgument(sel *ts.Node) string {
	part := sel.NamedChild(0)
	if part == nil || part.Kind() != "argument_part" {
		return ""
	}
	for _, args := range parsing.NamedChildren(part) {
		if args.Kind() != "arguments" || args.NamedChildCount() == 0 {
			continue
		}
		arg := args.NamedChild(0)
		if arg.Kind() == "argument" && arg.NamedChildCount() == 1 && arg.NamedChild(0).Kind() == "string_literal" {
			return c.tree.Text(arg.NamedChild(0))
		}
	}
	return ""
}

// localHosts are development addresses, including the Android emulator's alias
// for the host machine.
var localHosts = map[string]bool{"localhost": true, "127.0.0.1": true, "0.0.0.0": true, "10.0.2.2": true, "[::1]": true}

// insecureURL reports whether a Dart string literal is a plain http:// URL to a
// fixed, non-local host. Interpolated hosts are unknown and not reported.
func insecureURL(literal string) bool {
	s := strings.TrimLeft(literal, "rR")
	s = strings.TrimLeft(s, `'"`)
	rest, ok := strings.CutPrefix(s, "http://")
	if !ok {
		return false
	}
	host := rest
	if i := strings.IndexAny(rest, `/?#'"`); i >= 0 {
		host = rest[:i]
	}
	if h, _, found := strings.Cut(host, ":"); found && !strings.HasPrefix(host, "[") {
		host = h
	}
	return host != "" && !strings.HasPrefix(host, "$") && !localHosts[host]
}

// checkEmptyCatch flags catch and on clauses whose block has no statements and
// no comment explaining why the error is ignored.
func (c *checker) checkEmptyCatch(try *ts.Node) {
	body := try.ChildByFieldName("body")
	for _, child := range parsing.NamedChildren(try) {
		if child.Kind() != "block" || (body != nil && child.StartByte() == body.StartByte()) {
			continue
		}
		if child.NamedChildCount() == 0 {
			if !analysis.IsTestPath(c.path) { // tests catch errors on purpose (D-4)
				c.report("dart.empty-catch", child)
			}
		}
	}
}

// nestedFunctions start a new function scope inside a body.
var nestedFunctions = kinds("function_expression", "local_function_declaration")

// checkSetStateAfterAwait flags setState calls in an async body that follow an
// await with no reference to mounted (mounted or context.mounted) in between.
func (c *checker) checkSetStateAfterAwait(body *ts.Node) {
	var awaits, mounted []uint
	var calls []*ts.Node
	var walk func(n *ts.Node)
	walk = func(n *ts.Node) {
		if n == nil || n.IsError() || nestedFunctions[n.Kind()] {
			return
		}
		switch n.Kind() {
		case "await_expression":
			awaits = append(awaits, n.StartByte())
		case "identifier":
			if c.tree.Text(n) == "mounted" {
				mounted = append(mounted, n.StartByte())
			}
		case "selector":
			if primary, callee := c.call(n); callee == "setState" {
				calls = append(calls, primary)
			}
		}
		for _, child := range parsing.NamedChildren(n) {
			walk(child)
		}
	}
	for _, child := range parsing.NamedChildren(body) {
		walk(child)
	}
	for _, call := range calls {
		at := call.StartByte()
		last, awaited := uint(0), false
		for _, a := range awaits {
			if a < at && a >= last {
				last, awaited = a, true
			}
		}
		if !awaited {
			continue
		}
		guarded := false
		for _, m := range mounted {
			if m > last && m < at {
				guarded = true
			}
		}
		if !guarded {
			c.report("dart.set-state-after-await", call)
		}
	}
}

// disposableControllers hold listeners, tickers, or native resources and must
// be disposed by the State that creates them.
var disposableControllers = map[string]bool{
	"AnimationController": true, "TextEditingController": true, "ScrollController": true,
	"PageController": true, "TabController": true, "FocusNode": true,
}

// checkMissingDispose flags a State subclass that creates a controller but
// declares no dispose method.
func (c *checker) checkMissingDispose(class *ts.Node) {
	super := class.ChildByFieldName("superclass")
	body := class.ChildByFieldName("body")
	if super == nil || body == nil || super.NamedChildCount() == 0 || c.tree.Text(super.NamedChild(0)) != "State" {
		return
	}
	var created *ts.Node
	parsing.Walk(body, func(n *ts.Node) bool {
		if created != nil {
			return false
		}
		if n.Kind() == "selector" {
			if primary, callee := c.call(n); primary != nil {
				if name, _, _ := strings.Cut(callee, "."); disposableControllers[name] {
					created = primary
				}
			}
		}
		return true
	})
	if created == nil {
		return
	}
	for _, member := range parsing.NamedChildren(body) {
		if member.Kind() != "method_signature" {
			continue
		}
		for _, sig := range parsing.NamedChildren(member) {
			if name := sig.ChildByFieldName("name"); sig.Kind() == "function_signature" && name != nil && c.tree.Text(name) == "dispose" {
				return
			}
		}
	}
	c.report("dart.missing-dispose", created)
}
