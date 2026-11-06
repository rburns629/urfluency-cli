package javascript

import (
	"strings"

	ts "github.com/tree-sitter/go-tree-sitter"

	"github.com/rburns629/urfluency-cli/analysis"
	"github.com/rburns629/urfluency-cli/parsing"
)

func (c *checker) idiom(rule string, n *ts.Node) {
	c.findings = append(c.findings, analysis.Finding{Rule: rule, Path: c.path, Line: parsing.Line(n), Positive: true})
}

// utilityTypes are TypeScript's built-in type transformers.
var utilityTypes = map[string]bool{
	"Partial": true, "Required": true, "Readonly": true, "Pick": true, "Omit": true, "Record": true,
	"ReturnType": true, "Parameters": true, "Awaited": true, "NonNullable": true, "Exclude": true, "Extract": true,
}

// visitIdioms finds the JavaScript and TypeScript idioms that show fluency: each
// is a deliberate choice the language does not force.
func (c *checker) visitIdioms(n *ts.Node) bool {
	switch n.Kind() {
	case "optional_chain":
		c.idiom("js.idiom.optional-chaining", n)
	case "binary_expression":
		if op := n.ChildByFieldName("operator"); op != nil && op.Kind() == "??" {
			c.idiom("js.idiom.nullish-coalescing", n)
		}
	case "await_expression":
		c.idiom("js.idiom.async-await", n)
	case "object_pattern", "array_pattern":
		c.idiom("js.idiom.destructuring", n)
	case "call_expression":
		if fn := n.ChildByFieldName("function"); fn != nil && fn.Kind() == "member_expression" {
			switch text := c.tree.Text(fn); {
			case text == "Promise.all", text == "Promise.allSettled", text == "Promise.race", text == "Promise.any":
				c.idiom("js.idiom.concurrent-promises", n)
			case strings.HasPrefix(text, "Reflect."):
				c.idiom("js.construct.metaprogramming", n)
			case objectModel[text]:
				c.idiom("js.construct.object-model", n)
			}
		}
	case "new_expression":
		if ctor := n.ChildByFieldName("constructor"); ctor != nil && c.tree.Text(ctor) == "Proxy" {
			c.idiom("js.construct.metaprogramming", n)
		}
	case "generator_function_declaration", "generator_function":
		c.idiom("js.construct.generators", n)
	case "method_definition":
		if parsing.HasToken(n, "*") {
			c.idiom("js.construct.generators", n) // *[Symbol.iterator]() and other generator methods
		}
		if parsing.HasToken(n, "get", "set") {
			c.idiom("js.construct.object-model", n) // get size() and set size(v)
		}
	case "assignment_expression":
		// Foo.prototype.bar = ..., the pre-class way to give objects methods.
		if l := n.ChildByFieldName("left"); l != nil && l.Kind() == "member_expression" {
			if obj := l.ChildByFieldName("object"); obj != nil && strings.HasSuffix(c.tree.Text(obj), ".prototype") {
				c.idiom("js.construct.object-model", n)
			}
		}
	}
	if !c.typescript {
		return true
	}
	switch n.Kind() {
	case "type_parameters":
		c.idiom("ts.idiom.generics", n)
	case "union_type":
		if n.Parent() == nil || n.Parent().Kind() != "union_type" {
			c.idiom("ts.idiom.union-types", n)
		}
	case "type_predicate":
		c.idiom("ts.idiom.type-guard", n)
	case "interface_declaration", "type_alias_declaration":
		c.idiom("ts.idiom.declared-types", n)
	case "predefined_type":
		if c.tree.Text(n) == "unknown" {
			c.idiom("ts.idiom.unknown", n)
		}
	case "generic_type":
		if name := n.ChildByFieldName("name"); name != nil && utilityTypes[c.tree.Text(name)] {
			c.idiom("ts.idiom.utility-types", n)
		}
	case "conditional_type", "mapped_type_clause", "template_literal_type":
		c.idiom("ts.construct.type-level", n)
	}
	return true
}

// objectModel are the Object functions that shape objects themselves.
var objectModel = map[string]bool{
	"Object.defineProperty": true, "Object.defineProperties": true, "Object.create": true,
	"Object.setPrototypeOf": true, "Object.getPrototypeOf": true, "Object.getOwnPropertyDescriptor": true,
}
