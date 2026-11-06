package php

import (
	"strings"

	ts "github.com/tree-sitter/go-tree-sitter"
)

// magicMethods intercept property access and calls.
var magicMethods = map[string]bool{"__get": true, "__set": true, "__isset": true, "__unset": true, "__call": true, "__callstatic": true, "__invoke": true}

// visitConstructs records traits, generators, and metaprogramming: magic
// methods and reflection.
func (c *checker) visitConstructs(n *ts.Node) {
	switch n.Kind() {
	case "trait_declaration":
		c.idiom("php.construct.traits", n)
	case "yield_expression":
		c.idiom("php.construct.generators", n)
	case "method_declaration":
		if name := n.ChildByFieldName("name"); name != nil && magicMethods[strings.ToLower(c.tree.Text(name))] {
			c.idiom("php.construct.metaprogramming", n)
		}
	case "object_creation_expression":
		if strings.HasPrefix(strings.TrimPrefix(strings.TrimPrefix(c.tree.Text(n), "new"), " \\"), "Reflection") {
			c.idiom("php.construct.metaprogramming", n)
		}
	}
}
