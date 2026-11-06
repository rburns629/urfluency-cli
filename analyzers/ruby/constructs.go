package ruby

import ts "github.com/tree-sitter/go-tree-sitter"

// metaMethods define or change methods and classes at run time, the
// metaprogramming advanced Ruby is known for.
var metaMethods = map[string]bool{
	"define_method": true, "define_singleton_method": true, "instance_eval": true, "class_eval": true, "module_eval": true,
	"instance_exec": true, "class_exec": true, "instance_variable_get": true, "instance_variable_set": true, "const_get": true,
	"remove_method": true, "undef_method": true, "alias_method": true, "refine": true,
}

// hookMethods are the methods Ruby calls when code is defined or missing.
var hookMethods = map[string]bool{"method_missing": true, "respond_to_missing?": true, "included": true, "extended": true, "inherited": true, "prepended": true, "method_added": true}

// visitConstructs records metaprogramming: methods defined at run time,
// evaluated in another object's context, and the hooks Ruby calls.
func (c *checker) visitConstructs(n *ts.Node) {
	switch n.Kind() {
	case "call":
		if m := n.ChildByFieldName("method"); m != nil && metaMethods[c.tree.Text(m)] {
			c.idiom("ruby.construct.metaprogramming", n)
		}
	case "method", "singleton_method":
		if name := n.ChildByFieldName("name"); name != nil && hookMethods[c.tree.Text(name)] {
			c.idiom("ruby.construct.metaprogramming", n)
		}
	}
}
