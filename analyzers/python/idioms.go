package python

import (
	"strings"

	ts "github.com/tree-sitter/go-tree-sitter"

	"github.com/rburns629/urfluency-cli/analysis"
	"github.com/rburns629/urfluency-cli/parsing"
)

func (c *checker) idiom(rule string, n *ts.Node) {
	c.findings = append(c.findings, analysis.Finding{Rule: rule, Path: c.path, Line: parsing.Line(n), Positive: true})
}

// visitIdioms finds the Python idioms that show fluency: each is a deliberate
// choice the language does not force.
func (c *checker) visitIdioms(n *ts.Node) bool {
	switch n.Kind() {
	case "function_definition":
		if n.ChildByFieldName("return_type") != nil {
			c.idiom("py.idiom.type-hints", n)
		}
		if parsing.HasToken(n, "async") {
			c.idiom("py.idiom.async", n)
		}
		if name := n.ChildByFieldName("name"); name != nil && inClass(n) {
			switch method := c.tree.Text(name); {
			case protocolMethods[method]:
				c.idiom("py.construct.protocol-methods", n)
			case metaMethods[method]:
				c.idiom("py.construct.metaprogramming", n)
			}
		}
		if c.definesDecorator(n) {
			c.idiom("py.construct.decorator-definition", n)
		}
		if n.ChildByFieldName("type_parameters") != nil {
			c.idiom("py.construct.generic-typing", n) // def f[T](...), PEP 695
		}
	case "decorator":
		text := c.tree.Text(n)
		switch {
		case text == "@overload" || text == "@typing.overload":
			c.idiom("py.construct.generic-typing", n)
		case strings.Contains(text, "dataclass"):
			c.idiom("py.idiom.structured-data", n)
		case strings.Contains(text, "pytest.mark.parametrize"), strings.Contains(text, "pytest.fixture"):
			c.idiom("py.idiom.pytest", n)
		}
	case "class_definition":
		if bases := n.ChildByFieldName("superclasses"); bases != nil {
			text := c.tree.Text(bases)
			switch {
			case strings.Contains(text, "BaseModel"), strings.Contains(text, "TypedDict"), strings.Contains(text, "NamedTuple"):
				c.idiom("py.idiom.structured-data", n)
			case strings.Contains(text, "Exception"), strings.Contains(text, "Error"):
				c.idiom("py.idiom.custom-exception", n)
			case strings.Contains(text, "Protocol"):
				c.idiom("py.idiom.protocol", n)
			case text == "(type)":
				c.idiom("py.construct.metaprogramming", n) // a metaclass
			case strings.Contains(text, "Generic["):
				c.idiom("py.construct.generic-typing", n)
			}
		}
		if n.ChildByFieldName("type_parameters") != nil {
			c.idiom("py.construct.generic-typing", n) // class C[T], PEP 695
		}
	case "call":
		// T = TypeVar("T"), P = ParamSpec("P"), and the like.
		if fn := n.ChildByFieldName("function"); fn != nil && genericFactories[strings.TrimPrefix(c.tree.Text(fn), "typing.")] {
			c.idiom("py.construct.generic-typing", n)
		}
	case "with_statement":
		c.idiom("py.idiom.context-manager", n)
	case "list_comprehension", "dictionary_comprehension", "set_comprehension", "generator_expression":
		c.idiom("py.idiom.comprehension", n)
	case "yield":
		c.idiom("py.idiom.generator", n)
	case "string":
		if start := n.Child(0); start != nil && start.Kind() == "string_start" && strings.ContainsAny(c.tree.Text(start), "fF") {
			c.idiom("py.idiom.f-string", n)
		}
	case "import_from_statement":
		if m := n.ChildByFieldName("module_name"); m != nil && c.tree.Text(m) == "pathlib" {
			c.idiom("py.idiom.pathlib", n)
		}
	}
	return true
}

// protocolMethods make a class work with Python's own syntax: indexing,
// iteration, with, calls, operators, and comparison. __init__, __repr__, and
// __str__ are left out: nearly every class has them.
var protocolMethods = map[string]bool{
	"__getitem__": true, "__setitem__": true, "__delitem__": true, "__missing__": true, "__contains__": true,
	"__len__": true, "__iter__": true, "__next__": true, "__reversed__": true, "__aiter__": true, "__anext__": true,
	"__enter__": true, "__exit__": true, "__aenter__": true, "__aexit__": true, "__call__": true, "__bool__": true,
	"__eq__": true, "__ne__": true, "__lt__": true, "__le__": true, "__gt__": true, "__ge__": true, "__hash__": true,
	"__add__": true, "__sub__": true, "__mul__": true, "__truediv__": true, "__floordiv__": true, "__mod__": true,
	"__matmul__": true, "__and__": true, "__or__": true, "__xor__": true, "__neg__": true, "__radd__": true,
	"__iadd__": true, "__getattr__": true, "__setattr__": true, "__delattr__": true, "__format__": true,
	"__reduce__": true, "__getstate__": true, "__setstate__": true, "__copy__": true, "__deepcopy__": true,
}

// metaMethods customize attributes or classes themselves: descriptors and
// class creation hooks.
var metaMethods = map[string]bool{
	"__get__": true, "__set__": true, "__delete__": true, "__set_name__": true,
	"__init_subclass__": true, "__class_getitem__": true, "__prepare__": true,
}

// inClass reports whether a function is defined directly in a class body,
// decorated or not.
func inClass(fn *ts.Node) bool {
	p := fn.Parent()
	if p != nil && p.Kind() == "decorated_definition" {
		p = p.Parent()
	}
	return p != nil && p.Kind() == "block" && p.Parent() != nil && p.Parent().Kind() == "class_definition"
}

// definesDecorator reports whether a function is a decorator: it defines an
// inner function and returns it, or wraps it with functools.wraps.
func (c *checker) definesDecorator(fn *ts.Node) bool {
	body := fn.ChildByFieldName("body")
	if body == nil {
		return false
	}
	inner := map[string]bool{}
	wrapped := false
	for i := uint(0); i < body.NamedChildCount(); i++ {
		stmt := body.NamedChild(i)
		def := stmt
		if stmt.Kind() == "decorated_definition" {
			if strings.Contains(c.tree.Text(stmt), "wraps(") {
				wrapped = true
			}
			def = stmt.ChildByFieldName("definition")
		}
		if def != nil && def.Kind() == "function_definition" {
			if name := def.ChildByFieldName("name"); name != nil {
				inner[c.tree.Text(name)] = true
			}
		}
	}
	if len(inner) == 0 {
		return false
	}
	if wrapped {
		return true
	}
	for i := uint(0); i < body.NamedChildCount(); i++ {
		if stmt := body.NamedChild(i); stmt.Kind() == "return_statement" && stmt.NamedChildCount() == 1 {
			if v := stmt.NamedChild(0); v.Kind() == "identifier" && inner[c.tree.Text(v)] {
				return true
			}
		}
	}
	return false
}

// genericFactories make the type variables generic code is written with.
var genericFactories = map[string]bool{"TypeVar": true, "ParamSpec": true, "TypeVarTuple": true}
