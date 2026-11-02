package golang

import (
	"reflect"
	"testing"
)

func TestSecurityRules(t *testing.T) {
	src := `package a
import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"os/exec"
)
func f(ctx context.Context, db *sql.DB, id, dir string) {
	db.Query(fmt.Sprintf("SELECT * FROM t WHERE id = %s", id))
	db.ExecContext(ctx, "DELETE FROM t WHERE id = " + id)
	db.Query("SELECT * FROM t WHERE id = $1", id)
	db.Query("SELECT 1" + " FROM t")
	exec.Command("sh", "-c", "ls " + dir)
	exec.Command("sh", "-c", "ls")
	exec.Command("ls", dir)
	_ = &tls.Config{InsecureSkipVerify: true}
}`
	want := []string{"go.shell-command:14", "go.sql-string-built:10", "go.sql-string-built:11", "go.tls-insecure-skip-verify:17"}
	if got := findings(t, "a.go", src); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// An exec.CommandContext call without arguments does not compile, but a
// scanned repository can contain one; it must not crash the analyzer.
func TestCommandContextWithoutArguments(t *testing.T) {
	src := "package a\nimport \"os/exec\"\nfunc f() { exec.CommandContext() }\n"
	if got := findings(t, "a.go", src); len(got) != 0 {
		t.Errorf("got %v, want none", got)
	}
}

// A constant query split with + is not built from values.
func TestConstantSQLSplitAcrossLines(t *testing.T) {
	src := "package a\nimport \"database/sql\"\nfunc f(db *sql.DB, id string) {\n\tdb.Query(\"SELECT a \" + \"FROM t \" + \"WHERE x = $1\", 1)\n\tdb.Query(\"SELECT a FROM t WHERE x = \" + id)\n}\n"
	if got := findings(t, "a.go", src); !reflect.DeepEqual(got, []string{"go.sql-string-built:05"}) {
		t.Errorf("got %v, want only the query built from id", got)
	}
}

// A function literal assigned at package level is checked like a function.
func TestPackageLevelFunctionLiterals(t *testing.T) {
	decl := "package a\nimport \"os\"\nfunc g(ps []string) { for _, p := range ps { f, _ := os.Open(p); defer f.Close() } }\n"
	lit := "package a\nimport \"os\"\nvar g = func(ps []string) { for _, p := range ps { f, _ := os.Open(p); defer f.Close() } }\n"
	want := findings(t, "a.go", decl)
	if len(want) == 0 {
		t.Fatal("the function declaration has no findings to compare with")
	}
	if got := findings(t, "a.go", lit); !reflect.DeepEqual(got, want) {
		t.Errorf("package-level literal: %v, want %v as for the declaration", got, want)
	}
}
