package golang

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"
)

// sqlMethods are database/sql (and compatible) methods that take a query string.
var sqlMethods = map[string]bool{
	"Query": true, "QueryRow": true, "Exec": true, "Prepare": true,
	"QueryContext": true, "QueryRowContext": true, "ExecContext": true, "PrepareContext": true,
}

var shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "/bin/sh": true, "/bin/bash": true, "cmd": true, "cmd.exe": true, "powershell": true}

// checkSecurity applies call-based security rules.
func (c *checker) checkSecurity(call *ast.CallExpr) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	name := sel.Sel.Name
	offset := 0
	if strings.HasSuffix(name, "Context") {
		offset = 1
	}
	if sqlMethods[name] && len(call.Args) > offset && c.isBuiltString(call.Args[offset]) {
		c.report("go.sql-string-built", call.Pos())
	}
	if q := c.qualifiedName(call); (q == "os/exec.Command" || q == "os/exec.CommandContext") && len(call.Args) >= offset {
		args := call.Args[offset:]
		if len(args) >= 3 && shells[stringLit(args[0])] {
			flag := stringLit(args[1])
			if (flag == "-c" || flag == "/c" || flag == "-Command") && stringLit(args[2]) == "" {
				c.report("go.shell-command", call.Pos())
			}
		}
	}
}

// isBuiltString reports fmt.Sprintf calls and + concatenations with a non-literal.
//
// Only a value spliced where SQL expects a value counts: inside quotes, or
// after a comparison or LIKE. Table and column names, which placeholders
// cannot carry, and generated placeholder lists such as IN (?, ?) are how
// drivers and migrations must build SQL, and integers (%d) cannot inject.
func (c *checker) isBuiltString(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.CallExpr:
		if c.qualifiedName(e) != "fmt.Sprintf" || len(e.Args) == 0 {
			return false
		}
		if !constantString(e.Args[0]) {
			return true // a format built elsewhere can hold anything
		}
		for _, i := range valueVerbs(constantValue(e.Args[0])) {
			if i+1 >= len(e.Args) || !identifierName(e.Args[i+1]) {
				return true
			}
		}
		return false
	case *ast.BinaryExpr:
		return e.Op == token.ADD && !constantString(e) && concatSplicesValue(e)
	case *ast.ParenExpr:
		return c.isBuiltString(e.X)
	}
	return false
}

// valueVerbs returns the argument indexes of the %s, %v, and %q verbs a
// format string puts in a value position.
func valueVerbs(format string) []int {
	var out []int
	arg := 0
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		j := i + 1
		for j < len(format) && strings.ContainsRune("+-# 0123456789.[]*", rune(format[j])) {
			j++
		}
		if j >= len(format) {
			break
		}
		if format[j] == '%' {
			i = j
			continue
		}
		if verb := format[j]; (verb == 's' || verb == 'v' || verb == 'q') && valuePosition(format[:i]) {
			out = append(out, arg)
		}
		arg++
		i = j
	}
	return out
}

// identifierName reports whether an argument is named for a database name,
// such as tableName or seqName: Postgres takes sequence names as quoted
// strings, as in setval('%s', ...), and tables qualify columns after =.
func identifierName(e ast.Expr) bool {
	name := ""
	switch x := e.(type) {
	case *ast.Ident:
		name = x.Name
	case *ast.SelectorExpr:
		name = x.Sel.Name
	default:
		return false
	}
	lower := strings.ToLower(name)
	for _, s := range []string{"table", "column", "seq", "schema", "index", "constraint"} {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// constantValue joins the literals of a constant string expression.
func constantValue(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.BasicLit:
		return stringLit(x)
	case *ast.ParenExpr:
		return constantValue(x.X)
	case *ast.BinaryExpr:
		return constantValue(x.X) + constantValue(x.Y)
	}
	return ""
}

// concatSplicesValue reports whether a + concatenation joins a non-constant
// operand where the text before it leaves SQL expecting a value.
func concatSplicesValue(e *ast.BinaryExpr) bool {
	var parts []ast.Expr
	var flatten func(ast.Expr)
	flatten = func(x ast.Expr) {
		if b, ok := x.(*ast.BinaryExpr); ok && b.Op == token.ADD {
			flatten(b.X)
			flatten(b.Y)
			return
		}
		parts = append(parts, x)
	}
	flatten(e)
	before := ""
	for _, p := range parts {
		if constantString(p) {
			before += constantValue(p)
			continue
		}
		if valuePosition(before) && !identifierName(p) {
			return true
		}
		before = ""
	}
	return false
}

// valuePosition reports whether SQL text ending here expects a value next:
// an open single quote, or a comparison or LIKE.
func valuePosition(before string) bool {
	if strings.Count(strings.ReplaceAll(before, "''", ""), "'")%2 == 1 {
		return true
	}
	t := strings.ToUpper(strings.TrimRight(before, " \t\n"))
	for _, op := range []string{"=", "<", ">", " LIKE", " ILIKE"} {
		if strings.HasSuffix(t, op) {
			return true
		}
	}
	return false
}

// constantString reports literals and + concatenations of only literals, such
// as a query split across lines: "SELECT a " + "FROM t".
func constantString(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BasicLit:
		return true
	case *ast.ParenExpr:
		return constantString(e.X)
	case *ast.BinaryExpr:
		return e.Op == token.ADD && constantString(e.X) && constantString(e.Y)
	}
	return false
}

// stringLit returns the value of a string literal, or "" for anything else.
func stringLit(expr ast.Expr) string {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	v, err := strconv.Unquote(lit.Value)
	if err != nil {
		return ""
	}
	return v
}

// checkInsecureTLS flags InsecureSkipVerify: true.
func (c *checker) checkInsecureTLS(kv *ast.KeyValueExpr) {
	key, ok := kv.Key.(*ast.Ident)
	val, ok2 := kv.Value.(*ast.Ident)
	if ok && ok2 && key.Name == "InsecureSkipVerify" && val.Name == "true" && !c.suppressed(kv.Pos()) {
		c.report("go.tls-insecure-skip-verify", kv.Pos())
	}
}
