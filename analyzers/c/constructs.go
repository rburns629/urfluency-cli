package clang

import ts "github.com/tree-sitter/go-tree-sitter"

// visitConstructs records function pointers, variadic functions, and
// control of memory layout with unions and bit fields.
func (c *checker) visitConstructs(n *ts.Node) {
	switch n.Kind() {
	case "function_declarator":
		// int (*handler)(int): a pointer to a function, not a function.
		if d := n.ChildByFieldName("declarator"); d != nil && d.Kind() == "parenthesized_declarator" {
			c.idiom("c.construct.function-pointers", n)
		}
	case "variadic_parameter":
		c.idiom("c.construct.variadic", n)
	case "union_specifier":
		if n.ChildByFieldName("body") != nil {
			c.idiom("c.construct.memory-layout", n)
		}
	case "bitfield_clause":
		c.idiom("c.construct.memory-layout", n)
	}
}
