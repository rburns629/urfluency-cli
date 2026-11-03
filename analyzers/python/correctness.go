package python

import (
	"path"
	"strings"

	ts "github.com/tree-sitter/go-tree-sitter"

	"github.com/rburns629/urfluency-cli/parsing"
)

// Rules for code that runs but does the wrong thing: Python protocols
// implemented against their contract, error handling that handles nothing,
// and tests the test runner never runs. Each is narrow, so a finding is worth
// fixing in a project of any size.

// builtinBases are base classes that cannot contribute dataclass fields.
var builtinBases = map[string]bool{
	"object": true, "dict": true, "list": true, "set": true, "frozenset": true, "tuple": true, "str": true, "bytes": true,
	"int": true, "float": true, "Exception": true, "BaseException": true, "ValueError": true, "TypeError": true, "RuntimeError": true,
}

// checkDataclass flags a dataclass whose instances hold state its generated
// __eq__ never compares: no annotated fields, no base class that could have
// them, and either its own __init__ or a built-in container or value as its
// base. A field-less dataclass with neither is a stateless marker, for which
// every instance being equal is right.
func (c *checker) checkDataclass(decorated *ts.Node) {
	cls := decorated.ChildByFieldName("definition")
	if c.isTest || cls == nil || cls.Kind() != "class_definition" {
		return
	}
	isDataclass := false
	for _, d := range parsing.NamedChildren(decorated) {
		if d.Kind() != "decorator" {
			continue
		}
		text := strings.TrimSpace(strings.TrimPrefix(c.tree.Text(d), "@"))
		name, args, _ := strings.Cut(text, "(")
		if name != "dataclass" && name != "dataclasses.dataclass" {
			continue
		}
		if strings.Contains(strings.ReplaceAll(args, " ", ""), "eq=False") {
			return // no generated __eq__ to compare nothing
		}
		isDataclass = true
	}
	if !isDataclass {
		return
	}
	stateful := false
	if bases := cls.ChildByFieldName("superclasses"); bases != nil {
		for _, b := range parsing.NamedChildren(bases) {
			if b.Kind() != "identifier" || !builtinBases[c.tree.Text(b)] {
				return // a base class may declare the fields
			}
			stateful = stateful || c.tree.Text(b) != "object"
		}
	}
	for _, a := range classAssignments(cls) {
		if a.ChildByFieldName("type") != nil {
			return
		}
	}
	for _, m := range classMethods(cls) {
		if name := m.ChildByFieldName("name"); name != nil && c.tree.Text(name) == "__init__" {
			stateful = true
		}
	}
	if stateful {
		c.report("py.dataclass-without-fields", cls)
	}
}

// classAssignments returns the assignments directly in a class body.
func classAssignments(cls *ts.Node) []*ts.Node {
	body := cls.ChildByFieldName("body")
	if body == nil {
		return nil
	}
	var out []*ts.Node
	for _, stmt := range parsing.NamedChildren(body) {
		if stmt.Kind() != "expression_statement" {
			continue
		}
		for _, e := range parsing.NamedChildren(stmt) {
			if e.Kind() == "assignment" {
				out = append(out, e)
			}
		}
	}
	return out
}

// classMethods returns the functions directly in a class body, decorated or
// not.
func classMethods(cls *ts.Node) []*ts.Node {
	body := cls.ChildByFieldName("body")
	if body == nil {
		return nil
	}
	var out []*ts.Node
	for _, stmt := range parsing.NamedChildren(body) {
		switch stmt.Kind() {
		case "function_definition":
			out = append(out, stmt)
		case "decorated_definition":
			if def := stmt.ChildByFieldName("definition"); def != nil && def.Kind() == "function_definition" {
				out = append(out, def)
			}
		}
	}
	return out
}

// checkClass applies the rules that read a whole class.
func (c *checker) checkClass(cls *ts.Node) {
	for _, m := range classMethods(cls) {
		if name := m.ChildByFieldName("name"); name != nil && c.tree.Text(name) == "__getattr__" {
			c.checkGetattr(m)
		}
	}
	c.checkMutableClassAttributes(cls)
	c.checkContainerClass(cls)
	c.checkSetattr(cls)
}

// checkGetattr flags a __getattr__ method with no way to raise
// AttributeError: it neither raises one nor delegates to getattr, super(),
// __getattribute__, or another call given the name, any of which may raise it
// themselves. dict.get(name) is no delegation: it returns None. Stubs, such
// as a Protocol's ... or an abstract raise NotImplementedError, and tests are
// left alone.
func (c *checker) checkGetattr(fn *ts.Node) {
	body := fn.ChildByFieldName("body")
	if body == nil || c.isTest || c.stub(body) {
		return
	}
	text := c.tree.Text(body)
	for _, ok := range []string{"AttributeError", "getattr(", "super(", "__getattribute__"} {
		if strings.Contains(text, ok) {
			return
		}
	}
	name := ""
	if params := fn.ChildByFieldName("parameters"); params != nil {
		if ps := parsing.NamedChildren(params); len(ps) >= 2 {
			name = c.tree.Text(ps[1])
			if p := ps[1]; p.Kind() == "typed_parameter" && p.NamedChildCount() > 0 {
				name = c.tree.Text(p.NamedChild(0))
			}
		}
	}
	delegates := false
	parsing.Walk(body, func(n *ts.Node) bool {
		if n.Kind() != "call" || name == "" {
			return !delegates
		}
		callee, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
		if callee == nil || args == nil || strings.HasSuffix(c.tree.Text(callee), ".get") {
			return true
		}
		for _, a := range parsing.NamedChildren(args) {
			if c.tree.Text(a) == name {
				delegates = true
			}
		}
		return !delegates
	})
	if !delegates {
		c.report("py.getattr-without-attributeerror", fn)
	}
}

// stub reports a function body that only documents or defers: a docstring,
// pass, ..., or raise NotImplementedError.
func (c *checker) stub(body *ts.Node) bool {
	for _, s := range parsing.NamedChildren(body) {
		text := strings.TrimSpace(c.tree.Text(s))
		switch {
		case s.Kind() == "comment", s.Kind() == "pass_statement", text == "...":
		case s.Kind() == "expression_statement" && s.NamedChildCount() == 1 && s.NamedChild(0).Kind() == "string":
		case s.Kind() == "raise_statement" && strings.Contains(text, "NotImplementedError"):
		default:
			return false
		}
	}
	return true
}

var emptyContainers = map[string]bool{"[]": true, "{}": true, "list()": true, "dict()": true, "set()": true}

var mutatingMethods = map[string]bool{
	"append": true, "extend": true, "insert": true, "add": true, "update": true, "setdefault": true,
	"pop": true, "popitem": true, "remove": true, "discard": true, "clear": true,
}

// checkMutableClassAttributes flags an empty list, dict, or set assigned in a
// class body that a method then changes through self, which changes the one
// container every instance shares. A container changed through cls or the
// class name is a deliberate shared registry and is left alone.
func (c *checker) checkMutableClassAttributes(cls *ts.Node) {
	if c.isTest {
		return // test doubles record calls across instances on purpose
	}
	if name := cls.ChildByFieldName("name"); name != nil && (c.tree.Text(name) == "Meta" || c.tree.Text(name) == "Config") {
		return
	}
	candidates := map[string]*ts.Node{}
	for _, a := range classAssignments(cls) {
		left, right := a.ChildByFieldName("left"), a.ChildByFieldName("right")
		if a.ChildByFieldName("type") != nil || left == nil || right == nil || left.Kind() != "identifier" {
			continue
		}
		name := c.tree.Text(left)
		if strings.HasPrefix(name, "_") || strings.ToUpper(name) == name {
			continue // a private or constant container is usually shared on purpose
		}
		if emptyContainers[strings.ReplaceAll(c.tree.Text(right), " ", "")] {
			candidates[name] = a
		}
	}
	if len(candidates) == 0 {
		return
	}
	mutated := map[string]bool{}
	for _, m := range classMethods(cls) {
		parsing.Walk(m, func(n *ts.Node) bool {
			if name, ok := c.selfMutation(n); ok && candidates[name] != nil {
				mutated[name] = true
			}
			return true
		})
	}
	for name, a := range candidates {
		if mutated[name] {
			c.report("py.mutable-class-attribute", a)
		}
	}
}

// selfMutation reports the attribute a node changes in place through self:
// self.x.append(...) and the other mutating methods, or self.x[k] = v.
func (c *checker) selfMutation(n *ts.Node) (string, bool) {
	selfAttr := func(e *ts.Node) (string, bool) {
		if e == nil || e.Kind() != "attribute" {
			return "", false
		}
		obj, attr := e.ChildByFieldName("object"), e.ChildByFieldName("attribute")
		if obj == nil || attr == nil || c.tree.Text(obj) != "self" {
			return "", false
		}
		return c.tree.Text(attr), true
	}
	switch n.Kind() {
	case "call":
		fn := n.ChildByFieldName("function")
		if fn == nil || fn.Kind() != "attribute" {
			return "", false
		}
		if method := fn.ChildByFieldName("attribute"); method == nil || !mutatingMethods[c.tree.Text(method)] {
			return "", false
		}
		return selfAttr(fn.ChildByFieldName("object"))
	case "assignment", "augmented_assignment":
		if left := n.ChildByFieldName("left"); left != nil && left.Kind() == "subscript" {
			return selfAttr(left.ChildByFieldName("value"))
		}
	}
	return "", false
}

// checkReraise flags the last except clause of a try when all it does is
// raise the exception it caught, unchanged. An earlier clause that only
// re-raises can be deliberate, to keep a later, broader clause from catching
// that exception, and so is one beside an else clause, which needs it.
func (c *checker) checkReraise(clause *ts.Node) {
	try := c.tree.Parent(clause)
	if c.isTest || try == nil || try.Kind() != "try_statement" {
		return
	}
	var last *ts.Node
	for _, child := range parsing.NamedChildren(try) {
		switch child.Kind() {
		case "except_clause":
			last = child
		case "else_clause":
			return // try ... else needs an except clause, so except: raise is how to write it
		}
	}
	if last == nil || last.Id() != clause.Id() {
		return
	}
	bound := ""
	if value := clause.ChildByFieldName("value"); value != nil && value.Kind() == "as_pattern" {
		if alias := value.ChildByFieldName("alias"); alias != nil {
			bound = c.tree.Text(alias)
		}
	}
	var block *ts.Node
	for _, child := range parsing.NamedChildren(clause) {
		if child.Kind() == "block" {
			block = child
		}
	}
	if block == nil {
		return
	}
	var stmts []*ts.Node
	for _, s := range parsing.NamedChildren(block) {
		if s.Kind() != "comment" {
			stmts = append(stmts, s)
		}
	}
	if len(stmts) != 1 || stmts[0].Kind() != "raise_statement" || stmts[0].ChildByFieldName("cause") != nil {
		return
	}
	switch args := parsing.NamedChildren(stmts[0]); {
	case len(args) == 0:
		c.report("py.reraise-only-handler", clause)
	case len(args) == 1 && bound != "" && c.tree.Text(args[0]) == bound:
		c.report("py.reraise-only-handler", clause)
	}
}

// checkTestFile flags a script named like a test: a file in a tests folder,
// or at the root, named test_*.py or *_test.py, that runs code under
// if __name__ == "__main__", defines no test the runner would collect (no
// test function, Test class, or TestCase subclass), and asserts nothing. A
// helper module named like a test has no main block and is left alone.
func (c *checker) checkTestFile(root *ts.Node) {
	base := path.Base(c.path)
	if !(strings.HasPrefix(base, "test_") || strings.HasSuffix(base, "_test.py")) {
		return
	}
	// Scripts kept in package source, such as ones a test suite launches in
	// a subprocess, are not the suite's own files.
	if dir := path.Dir(c.path); dir != "." && !parsing.InDir(c.path, "tests", "test") {
		return
	}
	script := false
	for _, stmt := range parsing.NamedChildren(root) {
		if stmt.Kind() != "if_statement" {
			continue
		}
		if cond := stmt.ChildByFieldName("condition"); cond != nil && strings.Contains(c.tree.Text(cond), "__name__") && strings.Contains(c.tree.Text(cond), "__main__") {
			script = true
		}
	}
	if !script {
		return
	}
	found := false
	parsing.Walk(root, func(n *ts.Node) bool {
		if found {
			return false
		}
		switch n.Kind() {
		case "function_definition":
			if name := n.ChildByFieldName("name"); name != nil && strings.HasPrefix(c.tree.Text(name), "test") {
				found = true
			}
		case "class_definition":
			if name := n.ChildByFieldName("name"); name != nil && strings.HasPrefix(c.tree.Text(name), "Test") {
				found = true
			}
			if bases := n.ChildByFieldName("superclasses"); bases != nil && strings.Contains(c.tree.Text(bases), "TestCase") {
				found = true
			}
		}
		return !found
	})
	if found {
		return
	}
	asserts := false
	parsing.Walk(root, func(n *ts.Node) bool {
		switch n.Kind() {
		case "assert_statement":
			asserts = true
		case "call":
			if fn := n.ChildByFieldName("function"); fn != nil && strings.Contains(strings.ToLower(c.tree.Text(fn)), "assert") {
				asserts = true
			}
		case "identifier":
			asserts = asserts || c.tree.Text(n) == "AssertionError"
		}
		return !asserts
	})
	if !asserts {
		c.report("py.test-file-without-tests", root)
	}
}

// containerBases are the classes whose subclasses hold their data as items.
var containerBases = map[string]bool{
	"dict": true, "list": true, "set": true, "OrderedDict": true, "defaultdict": true, "UserDict": true, "UserList": true, "Counter": true,
}

// extendsContainer reports whether a class extends a built-in container,
// directly or as collections.X or dict[K, V].
func (c *checker) extendsContainer(cls *ts.Node) bool {
	bases := cls.ChildByFieldName("superclasses")
	if bases == nil {
		return false
	}
	for _, b := range parsing.NamedChildren(bases) {
		name, _, _ := strings.Cut(c.tree.Text(b), "[")
		if i := strings.LastIndex(name, "."); i >= 0 {
			name = name[i+1:]
		}
		if containerBases[strings.TrimSpace(name)] {
			return true
		}
	}
	return false
}

// method returns a class's method by name.
func method(t *parsing.Tree, cls *ts.Node, name string) *ts.Node {
	for _, m := range classMethods(cls) {
		if n := m.ChildByFieldName("name"); n != nil && t.Text(n) == name {
			return m
		}
	}
	return nil
}

// checkContainerClass applies the rules for classes that extend a
// container: options passed on as items, and entries copied into __dict__.
func (c *checker) checkContainerClass(cls *ts.Node) {
	if c.isTest || !c.extendsContainer(cls) {
		return
	}
	if init := method(c.tree, cls, "__init__"); init != nil {
		c.checkOptionsLeak(init)
	}
	// Entries are copied when one method stores them as items, through the
	// container's own __init__ or __setitem__, and also writes __dict__.
	// Restoring other attributes, as __setstate__ does after unpickling, is
	// not a copy.
	for _, m := range classMethods(cls) {
		var hit *ts.Node
		stores := false
		parsing.Walk(m, func(n *ts.Node) bool {
			switch n.Kind() {
			case "call":
				fn := n.ChildByFieldName("function")
				if fn == nil {
					return true
				}
				callee := c.tree.Text(fn)
				if strings.HasSuffix(callee, ".__init__") || strings.HasSuffix(callee, ".__setitem__") || strings.HasSuffix(callee, ".update") && callee != "self.__dict__.update" {
					stores = stores || strings.HasPrefix(callee, "super()") || strings.Contains(callee, "dict.") || strings.Contains(callee, "list.")
				}
				if callee == "self.__dict__.update" && hit == nil {
					hit = n
				}
			case "assignment", "augmented_assignment":
				if left := n.ChildByFieldName("left"); left != nil && left.Kind() == "subscript" {
					if v := left.ChildByFieldName("value"); v != nil && c.tree.Text(v) == "self.__dict__" && hit == nil {
						hit = n
					}
				}
			}
			return true
		})
		if hit != nil && stores {
			c.report("py.container-duplicated-state", hit)
			return
		}
	}
}

// checkOptionsLeak flags an __init__ that passes **kwargs to the container
// it extends and also reads options from kwargs, unless it pops them first.
func (c *checker) checkOptionsLeak(init *ts.Node) {
	params := init.ChildByFieldName("parameters")
	body := init.ChildByFieldName("body")
	if params == nil || body == nil {
		return
	}
	kw := ""
	for _, p := range parsing.NamedChildren(params) {
		if p.Kind() == "dictionary_splat_pattern" && p.NamedChildCount() > 0 {
			kw = c.tree.Text(p.NamedChild(0))
		}
	}
	if kw == "" {
		return
	}
	var forward *ts.Node
	popped, reads := false, false
	parsing.Walk(body, func(n *ts.Node) bool {
		switch n.Kind() {
		case "call":
			fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
			if fn == nil {
				return true
			}
			callee := c.tree.Text(fn)
			if strings.HasSuffix(callee, ".__init__") && args != nil && forward == nil {
				for _, a := range parsing.NamedChildren(args) {
					if a.Kind() == "dictionary_splat" && c.tree.Text(a) == "**"+kw {
						forward = n
					}
				}
			}
			if callee == kw+".pop" && forward == nil {
				popped = true
			}
			if callee == kw+".get" {
				reads = true
			}
		case "subscript":
			if v := n.ChildByFieldName("value"); v != nil && c.tree.Text(v) == kw {
				reads = true
			}
		case "comparison_operator":
			if parsing.HasToken(n, "in") {
				if ops := parsing.NamedChildren(n); len(ops) == 2 && c.tree.Text(ops[1]) == kw {
					reads = true
				}
			}
		}
		return true
	})
	if forward != nil && reads && !popped {
		c.report("py.container-options-leak", forward)
	}
}

// checkSetattr flags a __setattr__ that stores every name as an item, with
// no way through to the object's own attributes, in a class that sets
// attributes of its own: they become items. An attribute dict that sets
// none of its own is left alone.
func (c *checker) checkSetattr(cls *ts.Node) {
	if c.isTest {
		return
	}
	setattr := method(c.tree, cls, "__setattr__")
	if setattr == nil {
		return
	}
	body := setattr.ChildByFieldName("body")
	if body == nil {
		return
	}
	text := c.tree.Text(body)
	if !strings.Contains(text, "__setitem__(") && !strings.Contains(text, "self[") {
		return
	}
	for _, through := range []string{"object.__setattr__", "super(", "__dict__", ".__setattr__("} {
		if strings.Contains(text, through) {
			return
		}
	}
	sets := false
	for _, m := range classMethods(cls) {
		if m.Id() == setattr.Id() {
			continue
		}
		parsing.Walk(m, func(n *ts.Node) bool {
			if n.Kind() == "assignment" {
				if left := n.ChildByFieldName("left"); left != nil && left.Kind() == "attribute" {
					if obj := left.ChildByFieldName("object"); obj != nil && c.tree.Text(obj) == "self" {
						sets = true
					}
				}
			}
			return !sets
		})
	}
	if sets {
		c.report("py.setattr-into-items", setattr)
	}
}

// checkLoopElse flags a for or while loop with an else clause and no break
// of its own: the else always runs.
func (c *checker) checkLoopElse(loop *ts.Node) {
	if c.isTest {
		return
	}
	alt := loop.ChildByFieldName("alternative")
	body := loop.ChildByFieldName("body")
	if alt == nil || body == nil {
		return
	}
	breaks := false
	var visit func(n *ts.Node)
	visit = func(n *ts.Node) {
		for _, ch := range parsing.NamedChildren(n) {
			switch ch.Kind() {
			case "break_statement":
				breaks = true
			case "for_statement", "while_statement", "function_definition", "class_definition", "lambda":
				// A break there belongs to that loop; a nested loop's else
				// is checked on its own.
				if ch.Kind() == "for_statement" || ch.Kind() == "while_statement" {
					if a := ch.ChildByFieldName("alternative"); a != nil {
						visit(a)
					}
				}
			default:
				visit(ch)
			}
		}
	}
	visit(body)
	if !breaks {
		c.report("py.loop-else-without-break", alt)
	}
}
