package cpp

import (
	"fmt"

	ts "github.com/tree-sitter/go-tree-sitter"

	"github.com/roburns/urfluency-cli/parsing"
)

// method is one member function declared in a class body.
type method struct {
	node       *ts.Node
	signature  string // name and parameter count
	virtual    bool
	overriding bool // marked override or final
}

// class is a class or struct defined in the file, with the bases it names.
type class struct {
	bases   []string
	methods []method
}

// checkOverrides flags member functions that override a virtual function of a
// base class defined in the same file without saying override or final. Bases
// defined elsewhere are unknown, so they are never reported.
func (c *checker) checkOverrides() {
	classes, ambiguous := map[string]*class{}, map[string]bool{}
	var order []*class
	for _, n := range c.classes {
		name := n.ChildByFieldName("name")
		if name == nil {
			continue
		}
		cl := &class{methods: c.methods(n.ChildByFieldName("body"))}
		for _, child := range parsing.NamedChildren(n) {
			if child.Kind() == "base_class_clause" {
				cl.bases = c.baseNames(child)
			}
		}
		if _, dup := classes[c.tree.Text(name)]; dup {
			ambiguous[c.tree.Text(name)] = true
		} else {
			classes[c.tree.Text(name)] = cl
		}
		order = append(order, cl)
	}
	// Bases are resolved by bare name, so a name defined twice, as in two
	// namespaces, could be either; it is treated as defined elsewhere.
	for name := range ambiguous {
		delete(classes, name)
	}
	// Only a method whose signature is virtual somewhere in the file can
	// override one. Collecting every class's inherited virtuals instead
	// re-walked each base chain per class, quadratic in the chain's length.
	virtualSigs := map[string]bool{}
	for _, cl := range order {
		for _, m := range cl.methods {
			if m.virtual || m.overriding {
				virtualSigs[m.signature] = true
			}
		}
	}
	visited, search := map[string]int{}, 0
	for _, cl := range order {
		for _, m := range cl.methods {
			if m.overriding || !virtualSigs[m.signature] {
				continue
			}
			search++
			if inheritsVirtual(classes, cl.bases, m.signature, visited, search) {
				c.report("cpp.missing-override", m.node)
			}
		}
	}
}

// inheritsVirtual reports whether one of the named bases, or a base of theirs,
// declares sig virtual or override. visited marks the classes this search,
// numbered search, has already looked at, so diamonds and cycles end.
func inheritsVirtual(classes map[string]*class, bases []string, sig string, visited map[string]int, search int) bool {
	for _, b := range bases {
		cl, ok := classes[b]
		if !ok || visited[b] == search {
			continue
		}
		visited[b] = search
		for _, m := range cl.methods {
			if (m.virtual || m.overriding) && m.signature == sig {
				return true
			}
		}
		if inheritsVirtual(classes, cl.bases, sig, visited, search) {
			return true
		}
	}
	return false
}

// baseNames returns the unqualified names of the base classes, without
// template arguments.
func (c *checker) baseNames(clause *ts.Node) []string {
	var out []string
	for _, b := range parsing.NamedChildren(clause) {
		for b.Kind() == "qualified_identifier" && b.ChildByFieldName("name") != nil {
			b = b.ChildByFieldName("name")
		}
		if b.Kind() == "template_type" && b.ChildByFieldName("name") != nil {
			b = b.ChildByFieldName("name")
		}
		if b.Kind() == "type_identifier" {
			out = append(out, c.tree.Text(b))
		}
	}
	return out
}

// methods returns the member functions declared or defined in a class body,
// excluding destructors.
func (c *checker) methods(body *ts.Node) []method {
	if body == nil {
		return nil
	}
	var out []method
	for _, member := range parsing.NamedChildren(body) {
		switch member.Kind() {
		case "field_declaration", "declaration", "function_definition":
		default:
			continue
		}
		fd := functionDeclarator(member.ChildByFieldName("declarator"))
		if fd == nil {
			continue
		}
		name := fd.ChildByFieldName("declarator")
		params := fd.ChildByFieldName("parameters")
		if name == nil || params == nil || name.Kind() == "destructor_name" {
			continue
		}
		out = append(out, method{
			node:       member,
			signature:  fmt.Sprintf("%s/%d", c.tree.Text(name), params.NamedChildCount()),
			virtual:    parsing.HasToken(member, "virtual"),
			overriding: parsing.HasToken(fd, "virtual_specifier"),
		})
	}
	return out
}

// functionDeclarator finds the function declarator under pointer and reference
// return types, such as Foo* get() or const Foo& get().
func functionDeclarator(d *ts.Node) *ts.Node {
	for d != nil {
		switch d.Kind() {
		case "function_declarator":
			return d
		case "pointer_declarator", "reference_declarator":
			if next := d.ChildByFieldName("declarator"); next != nil {
				d = next
			} else if d.NamedChildCount() > 0 {
				d = d.NamedChild(0)
			} else {
				return nil
			}
		default:
			return nil
		}
	}
	return nil
}
