package golang

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"github.com/roburns/urfluency-cli/analysis"
)

// idiom records a positive finding: an idiom the code uses well.
func (c *checker) idiom(rule string, pos token.Pos) {
	c.findings = append(c.findings, analysis.Finding{Rule: rule, Path: c.path, Line: c.fset.Position(pos).Line, Positive: true})
}

// idioms finds the Go idioms that show fluency: they are each a deliberate
// choice the language does not force.
func (c *checker) idioms() {
	isTest := analysis.IsTestPath(c.path)
	ast.Inspect(c.file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncDecl:
			if n.Type.TypeParams != nil {
				c.idiom("go.idiom.generics", n.Pos())
			}
			if c.returnsIterator(n.Type) {
				c.idiom("go.construct.iterators", n.Pos())
			}
			if directional(n.Type) {
				c.idiom("go.construct.channels", n.Pos())
			}
			if params := n.Type.Params.List; len(params) > 0 && c.isContext(params[0].Type) {
				c.idiom("go.idiom.context-first", n.Pos())
			}
			if n.Recv != nil && n.Name.Name == "Error" && len(n.Type.Params.List) == 0 &&
				n.Type.Results != nil && len(n.Type.Results.List) == 1 && isIdent(n.Type.Results.List[0].Type, "string") {
				c.idiom("go.idiom.custom-error-type", n.Pos())
			}
		case *ast.TypeSpec:
			if n.TypeParams != nil {
				c.idiom("go.idiom.generics", n.Pos())
			}
			if it, ok := n.Type.(*ast.InterfaceType); ok && len(it.Methods.List) >= 1 && len(it.Methods.List) <= 3 {
				c.idiom("go.idiom.small-interface", n.Pos())
			}
		case *ast.CallExpr:
			switch c.callee(n) {
			case "fmt.Errorf":
				if len(n.Args) > 0 && strings.Contains(stringValue(n.Args[0]), "%w") {
					c.idiom("go.idiom.error-wrapping", n.Pos())
				}
			case "errors.Is", "errors.As":
				c.idiom("go.idiom.error-inspection", n.Pos())
			case "errgroup.WithContext", "semaphore.NewWeighted":
				c.idiom("go.idiom.structured-concurrency", n.Pos())
			}
		case *ast.SelectorExpr:
			// Each use of a package's name once, whether called or as a type:
			// atomic.AddInt64 and atomic.Int64, reflect.TypeOf and
			// reflect.Value, and sync.Once, sync.Pool, and the like.
			switch path := c.importPath(n); {
			case path == "sync/atomic":
				c.idiom("go.construct.sync", n.Pos())
			case path == "sync" && advancedSync[n.Sel.Name]:
				c.idiom("go.construct.sync", n.Pos())
			case path == "reflect":
				c.idiom("go.construct.reflection", n.Pos())
			}
		case *ast.DeferStmt:
			if sel, ok := n.Call.Fun.(*ast.SelectorExpr); ok {
				switch sel.Sel.Name {
				case "Close", "Unlock", "RUnlock", "Done", "Stop":
					c.idiom("go.idiom.defer-cleanup", n.Pos())
				}
			} else if isIdent(n.Call.Fun, "cancel") {
				c.idiom("go.idiom.defer-cleanup", n.Pos())
			}
		case *ast.SelectStmt:
			cases := 0
			for _, s := range n.Body.List {
				if cc, ok := s.(*ast.CommClause); ok && cc.Comm != nil {
					cases++
				}
			}
			for _, s := range n.Body.List {
				if cc, ok := s.(*ast.CommClause); ok && receivesDone(cc.Comm) {
					c.idiom("go.idiom.cancellation", n.Pos())
					cases-- // waiting for cancellation is its own idiom
					break
				}
			}
			if cases >= 2 {
				c.idiom("go.construct.channels", n.Pos())
			}
		case *ast.RangeStmt:
			if isTest && containsSubtest(n.Body) {
				c.idiom("go.idiom.table-driven-test", n.Pos())
			}
		}
		return true
	})
}

// callee returns "pkg.Func" for a call to an imported package's function, using
// the import path's last element so renamed imports still match.
func (c *checker) callee(call *ast.CallExpr) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	path, ok := c.imports[pkg.Name]
	if !ok {
		return ""
	}
	return path[strings.LastIndex(path, "/")+1:] + "." + sel.Sel.Name
}

func (c *checker) isContext(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Context" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && c.imports[pkg.Name] == "context"
}

func isIdent(expr ast.Expr, name string) bool {
	id, ok := expr.(*ast.Ident)
	return ok && id.Name == name
}

func stringValue(expr ast.Expr) string {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return ""
	}
	return s
}

// containsSubtest reports whether a loop body calls t.Run.
func containsSubtest(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Run" {
				if id, ok := sel.X.(*ast.Ident); ok && (id.Name == "t" || id.Name == "b") {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// advancedSync are the sync types beyond Mutex and WaitGroup, which every
// concurrent program uses.
var advancedSync = map[string]bool{"Once": true, "OnceFunc": true, "OnceValue": true, "Pool": true, "RWMutex": true, "Cond": true, "Map": true}

// importPath returns the import path of the package a selector names, as
// "sync/atomic" for atomic.AddInt64, or "".
func (c *checker) importPath(e ast.Expr) string {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return c.imports[pkg.Name]
}

// returnsIterator reports whether a function returns an iter.Seq or Seq2.
func (c *checker) returnsIterator(ft *ast.FuncType) bool {
	if ft.Results == nil {
		return false
	}
	for _, r := range ft.Results.List {
		t := r.Type
		if ix, ok := t.(*ast.IndexExpr); ok {
			t = ix.X
		} else if ix, ok := t.(*ast.IndexListExpr); ok {
			t = ix.X
		}
		if c.importPath(t) == "iter" {
			return true
		}
	}
	return false
}

// directional reports whether a function takes or returns a send-only or
// receive-only channel.
func directional(ft *ast.FuncType) bool {
	for _, fl := range []*ast.FieldList{ft.Params, ft.Results} {
		if fl == nil {
			continue
		}
		for _, f := range fl.List {
			if ch, ok := f.Type.(*ast.ChanType); ok && ch.Dir != ast.SEND|ast.RECV {
				return true
			}
		}
	}
	return false
}
