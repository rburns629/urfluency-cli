// Package java analyzes Java source with tree-sitter. It parses files and never
// compiles or runs them.
package java

import (
	"bytes"
	"context"
	"path"
	"strings"

	ts "github.com/tree-sitter/go-tree-sitter"

	"github.com/rburns629/urfluency-cli/analysis"
	"github.com/rburns629/urfluency-cli/parsing"
)

func init() { analysis.Register(Analyzer{}) }

// Analyzer implements analysis.Analyzer for Java.
type Analyzer struct{}

func (Analyzer) Language() string     { return "java" }
func (Analyzer) Extensions() []string { return []string{".java"} }

// SkipPath excludes Maven and Gradle build output and Android's generated R and
// BuildConfig classes.
func (Analyzer) SkipPath(p string) bool {
	base := path.Base(p)
	return base == "R.java" || base == "BuildConfig.java" || parsing.InDir(p, "target", "build", "out", ".gradle")
}

// Skip excludes build output and generated files. Markers are looked for only in
// the file header, before the first type body opens, so a user's own @Generated
// annotation on a method does not exclude the whole file.
func (a Analyzer) Skip(f analysis.File) bool {
	if a.SkipPath(f.Path) {
		return true
	}
	// Only the file's header, before the first class body, says so.
	head := f.Content[:min(len(f.Content), 4096)]
	if i := bytes.IndexByte(head, '{'); i >= 0 {
		head = head[:i]
	}
	return parsing.GeneratedHeader(head)
}

// Complexity is the cognitive-complexity syntax for Java. Java has no else
// node: the else keyword is an anonymous token of if_statement, which
// ElseToken counts once per branch, and the if of an "else if" follows that
// token and is not counted again. Method calls have no function field, so
// recursion is not counted.
var Complexity = parsing.ComplexitySyntax{
	Functions: set("method_declaration", "constructor_declaration", "compact_constructor_declaration", "lambda_expression"),
	Structures: set("if_statement", "for_statement", "enhanced_for_statement", "while_statement", "do_statement",
		"switch_expression", "catch_clause", "ternary_expression"),
	ElseToken:  "else",
	Logical:    "binary_expression",
	LogicalOps: set("&&", "||"),
	Jumps:      set("break_statement", "continue_statement"),
	Label:      "identifier",
}

func set(kinds ...string) map[string]bool {
	m := make(map[string]bool, len(kinds))
	for _, k := range kinds {
		m[k] = true
	}
	return m
}

// Analyze applies every Java rule to each file.
func (Analyzer) Analyze(ctx context.Context, files []analysis.File) ([]analysis.Finding, error) {
	var findings []analysis.Finding
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		tree, err := parsing.Parse(parsing.Java, f.Content)
		if err != nil {
			continue
		}
		c := checker{tree: tree, path: f.Path, isTest: analysis.IsTestPath(f.Path), shadowed: shadowedTypes(tree)}
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
	tree     *parsing.Tree
	path     string
	isTest   bool
	shadowed map[string]bool // simple type names imported from outside java.util
	findings []analysis.Finding
}

func (c *checker) report(rule string, n *ts.Node) {
	c.findings = append(c.findings, analysis.Finding{Rule: rule, Path: c.path, Line: parsing.Line(n)})
}

func (c *checker) visit(n *ts.Node) bool {
	switch n.Kind() {
	case "method_invocation":
		c.checkInvocation(n)
	case "object_creation_expression":
		c.checkCreation(n)
	case "method_declaration":
		if !c.isTest {
			c.checkTrustAll(n)
		}
	case "lambda_expression":
		if !c.isTest && c.permissiveVerifierLambda(n) {
			c.report("java.trust-all-certificates", n)
		}
	case "field_access":
		if !c.isTest && c.text(n.ChildByFieldName("object")) == "NoopHostnameVerifier" {
			c.report("java.trust-all-certificates", n)
		}
	case "catch_clause":
		c.checkCatch(n)
	case "binary_expression":
		if op := operator(n); op == "==" || op == "!=" {
			if kindOf(n.ChildByFieldName("left")) == "string_literal" || kindOf(n.ChildByFieldName("right")) == "string_literal" {
				c.report("java.string-equality", n)
			}
		}
	case "type_identifier":
		c.checkRawType(n)
	}
	return true
}

// checkInvocation applies the rules that look at method calls.
func (c *checker) checkInvocation(n *ts.Node) {
	name := c.text(n.ChildByFieldName("name"))
	args := argumentNodes(n)
	switch {
	case sqlMethods[name] && len(args) > 0 && c.sqlConcatenation(args[0]):
		c.report("java.sql-string-built", n)
	case name == "exec" && strings.HasSuffix(c.text(n.ChildByFieldName("object")), "getRuntime()") &&
		len(args) > 0 && c.dynamicConcatenation(args[0]):
		c.report("java.command-built", n)
	case name == "printStackTrace" && len(args) == 0 && !c.isTest:
		c.report("java.print-stack-trace", n)
	}
}

// checkCreation applies the rules that look at constructor calls.
func (c *checker) checkCreation(n *ts.Node) {
	typeName := simpleName(c.text(n.ChildByFieldName("type")))
	switch typeName {
	case "ProcessBuilder":
		c.checkProcessBuilder(n)
	case "ObjectInputStream", "XMLDecoder":
		if !c.isTest && !hasChildKind(n, "class_body") && !c.filtered(n) {
			c.report("java.unsafe-deserialization", n)
		}
	case "NoopHostnameVerifier":
		if !c.isTest {
			c.report("java.trust-all-certificates", n)
		}
	}
}

// checkCatch flags catch blocks with nothing in them, not even a comment. A
// parameter named ignored or expected states the intent, so it is exempt.
func (c *checker) checkCatch(n *ts.Node) {
	body := n.ChildByFieldName("body")
	if body == nil || body.NamedChildCount() > 0 {
		return
	}
	for _, p := range parsing.NamedChildren(n) {
		if p.Kind() == "catch_formal_parameter" {
			switch strings.ToLower(c.text(p.ChildByFieldName("name"))) {
			case "ignored", "ignore", "expected", "_":
				return
			}
		}
	}
	if !analysis.IsTestPath(c.path) { // tests catch errors on purpose (D-4)
		c.report("java.empty-catch", n)
	}
}

// rawCandidates are JDK generic types that are almost always meant to carry type
// arguments.
var rawCandidates = set("List", "ArrayList", "LinkedList", "Map", "HashMap", "LinkedHashMap", "TreeMap",
	"Set", "HashSet", "LinkedHashSet", "TreeSet", "Collection", "Iterator", "Optional", "Comparator",
	"Queue", "Deque", "ArrayDeque")

// rawContexts are the parents in which a bare type name declares or creates a
// value: fields, locals, parameters, return types, new expressions, and type
// arguments. Casts, instanceof, and class literals legitimately use raw names.
var rawContexts = set("field_declaration", "local_variable_declaration", "formal_parameter", "method_declaration",
	"object_creation_expression", "type_arguments")

// checkRawType flags a generic JDK type used without type arguments where a
// value is declared or created, unless the file imports a non-JDK type of that
// name (java.awt.List) or suppresses rawtypes.
func (c *checker) checkRawType(n *ts.Node) {
	name := c.text(n)
	parent := n.Parent()
	if !rawCandidates[name] || c.shadowed[name] || parent == nil || !rawContexts[parent.Kind()] {
		return
	}
	for p := parent; p != nil; p = c.tree.Parent(p) {
		if mods := childOfKind(p, "modifiers"); mods != nil && strings.Contains(c.text(mods), `"rawtypes"`) {
			return
		}
	}
	c.report("java.raw-type", n)
}

// shadowedTypes returns simple names imported from packages other than
// java.util, such as java.awt.List, and types the file declares, such as its
// own Entry, so they are not mistaken for raw JDK types.
func shadowedTypes(t *parsing.Tree) map[string]bool {
	out := map[string]bool{}
	parsing.Walk(t.Root(), func(n *ts.Node) bool {
		switch n.Kind() {
		case "class_declaration", "interface_declaration", "enum_declaration", "record_declaration":
			if name := n.ChildByFieldName("name"); name != nil {
				out[t.Text(name)] = true
			}
		}
		return true
	})
	for _, imp := range imports(t) {
		if strings.HasPrefix(imp, "java.util.") {
			continue
		}
		if strings.HasSuffix(imp, ".*") {
			if imp == "java.awt.*" {
				out["List"] = true
			}
			continue
		}
		out[simpleName(imp)] = true
	}
	return out
}

// imports returns each imported name, with ".*" for on-demand imports.
func imports(t *parsing.Tree) []string {
	var out []string
	for _, n := range parsing.NamedChildren(t.Root()) {
		if n.Kind() != "import_declaration" {
			continue
		}
		var name string
		wildcard := false
		for _, child := range parsing.NamedChildren(n) {
			switch child.Kind() {
			case "scoped_identifier", "identifier":
				name = t.Text(child)
			case "asterisk":
				wildcard = true
			}
		}
		if wildcard {
			name += ".*"
		}
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

func (c *checker) text(n *ts.Node) string {
	if n == nil {
		return ""
	}
	return c.tree.Text(n)
}

func kindOf(n *ts.Node) string {
	if n == nil {
		return ""
	}
	return n.Kind()
}

func operator(n *ts.Node) string {
	if op := n.ChildByFieldName("operator"); op != nil {
		return op.Kind()
	}
	return ""
}

// simpleName strips a package qualifier and type arguments: java.io.File → File.
func simpleName(s string) string {
	if i := strings.IndexByte(s, '<'); i >= 0 {
		s = s[:i]
	}
	return s[strings.LastIndexByte(s, '.')+1:]
}

// argumentNodes returns a call's arguments, or nil when it has none.
func argumentNodes(n *ts.Node) []*ts.Node {
	if args := n.ChildByFieldName("arguments"); args != nil {
		return parsing.NamedChildren(args)
	}
	return nil
}

func hasChildKind(n *ts.Node, kind string) bool { return childOfKind(n, kind) != nil }

func childOfKind(n *ts.Node, kind string) *ts.Node {
	for _, child := range parsing.NamedChildren(n) {
		if child.Kind() == kind {
			return child
		}
	}
	return nil
}
