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

// Names spliced where placeholders cannot go, placeholder lists, and integers
// are not injection; values spliced where SQL expects one are.
func TestSQLValuePositions(t *testing.T) {
	src := `package a
import (
	"database/sql"
	"fmt"
	"strings"
)
func f(db *sql.DB, table, name, seqName string, n int, ids []any) {
	db.Exec(fmt.Sprintf("DROP TABLE %s", table))
	db.Exec(fmt.Sprintf("SET IDENTITY_INSERT ` + "`%s`" + ` ON", table))
	db.Query(fmt.Sprintf("SELECT * FROM t WHERE id IN (%s)", strings.Repeat("?,", len(ids))), ids...)
	db.Query(fmt.Sprintf("SELECT * FROM t LIMIT %d", n))
	db.Query("SELECT * FROM " + table + " WHERE id = $1", n)
	db.Query(fmt.Sprintf("SELECT * FROM t WHERE name = '%s'", name))
	db.Query(fmt.Sprintf("SELECT * FROM t WHERE name LIKE '%%%s%%'", name))
	db.Query(fmt.Sprintf("SELECT * FROM %s WHERE n > %v", table, name))
	db.Query("SELECT * FROM t WHERE name = '" + name + "'")
	db.Exec(fmt.Sprintf("SELECT setval('%s', %d)", seqName, n))
	db.Query(fmt.Sprintf("INSERT INTO %s (a) "+"VALUES (?) ON CONFLICT DO UPDATE SET a = %s.a+1", table, table))
	db.Query(fmt.Sprintf("SELECT * FROM t "+"WHERE name = '%s'", name))
}`
	want := []string{"go.sql-string-built:13", "go.sql-string-built:14", "go.sql-string-built:15", "go.sql-string-built:16", "go.sql-string-built:19"}
	if got := findings(t, "a.go", src); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// Tests reach no user: TLS checks off for httptest and queries from
// fixtures are not findings there.
func TestSecurityRulesSkipTests(t *testing.T) {
	src := "package a\nimport (\n\t\"crypto/tls\"\n\t\"database/sql\"\n)\nfunc f(db *sql.DB, id string) {\n\t_ = &tls.Config{InsecureSkipVerify: true}\n\tdb.Query(\"SELECT 1 WHERE id = \" + id)\n}\n"
	if got := findings(t, "a_test.go", src); len(got) != 0 {
		t.Errorf("got %v, want none in a test", got)
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

// After waiting for cancellation, as a graceful shutdown does, a fresh
// context is right; tests may use one anywhere; and a client with its own
// Transport sets its limits there.
func TestFreshContextAndTransportExceptions(t *testing.T) {
	src := `package a
import (
	"context"
	"crypto/tls"
	"net/http"
	"time"
)
func shutdown(ctx context.Context, s *http.Server) {
	<-ctx.Done()
	c, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s.Shutdown(c)
}
func handle(ctx context.Context) {
	run(context.Background())
}
func clients(tr *http.Transport) {
	_ = &http.Client{Transport: tr}
	_ = &http.Client{}
}
func bounded(ctx context.Context) {
	_ = &http.Client{}
	http.DefaultClient.Do(nil)
	http.Get("https://example.com")
}
func deadline() {
	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()
	_ = ctx
	http.DefaultClient.Do(nil)
	_ = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
}
func run(context.Context) {}`
	want := []string{"go.context-background-in-handler:15", "go.http-without-timeout:19", "go.http-without-timeout:24"}
	if got := findings(t, "a.go", src); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if got := findings(t, "a_test.go", src); len(got) != 0 {
		t.Errorf("test file: got %v, want none", got)
	}
}
