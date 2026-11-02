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
func (c *checker) isBuiltString(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.CallExpr:
		return c.qualifiedName(e) == "fmt.Sprintf"
	case *ast.BinaryExpr:
		return e.Op == token.ADD && !constantString(e)
	case *ast.ParenExpr:
		return c.isBuiltString(e.X)
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
	if ok && ok2 && key.Name == "InsecureSkipVerify" && val.Name == "true" {
		c.report("go.tls-insecure-skip-verify", kv.Pos())
	}
}
