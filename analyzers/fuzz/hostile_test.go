package fuzz

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rburns629/urfluency-cli/analysis"
	"github.com/rburns629/urfluency-cli/parsing"
)

func analyzeTime(t *testing.T, path, src string) time.Duration {
	t.Helper()
	a := analysis.ForPath(path)
	if a == nil {
		t.Fatalf("no analyzer for %s", path)
	}
	start := time.Now()
	if _, err := a.Analyze(context.Background(), []analysis.File{{Path: path, Content: []byte(src)}}); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return time.Since(start)
}

// linear fails when analyzing an input four times as large takes more than ten
// times as long: linear work takes four times as long, quadratic sixteen. A
// ratio, unlike a fixed limit, holds on slow machines and under the race
// detector; times under 200 ms are too noisy to compare. A grammar can be
// slow on an input itself, which ParseBudget bounds by cutting the parse off:
// if the time collapses under a tiny budget, the budget is what bounds it.
func linear(t *testing.T, label, path string, gen func(n int) string, n int) {
	t.Helper()
	small, large := analyzeTime(t, path, gen(n)), analyzeTime(t, path, gen(4*n))
	if large > 200*time.Millisecond && large > 10*small {
		defer func(b time.Duration) { parsing.ParseBudget = b }(parsing.ParseBudget)
		parsing.ParseBudget = 20 * time.Millisecond
		if cut := analyzeTime(t, path, gen(4*n)); cut < large/4 {
			t.Logf("%s: the parse is slow, and ParseBudget cuts it off (%s, %s with a 20 ms budget)", label,
				large.Round(time.Millisecond), cut.Round(time.Millisecond))
			return
		}
		t.Errorf("%s: %s at size %d, %s at %d; work grows faster than the input", label, small.Round(time.Millisecond), n,
			large.Round(time.Millisecond), 4*n)
	}
}

// Inputs that once made an analyzer quadratic or worse, taking from 10 s to
// minutes at a few hundred kilobytes.
func TestHostileInputsStayLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	linear(t, "Dart call chain", "lib/a.dart", func(n int) string { return "void f() { x" + strings.Repeat(".a()", n) + "; }\n" }, 1000)
	linear(t, "Python nested calls", "a.py", func(n int) string {
		return "x = " + strings.Repeat("open(", n) + "p" + strings.Repeat(")", n) + "\n"
	}, 200)
	linear(t, "Rust casts", "a.rs", func(n int) string {
		var b strings.Builder
		b.WriteString("pub fn f() {\n")
		for i := range n {
			fmt.Fprintf(&b, "    let a%d: i64 = 1;\n    let b%d = a%d as u8;\n", i, i, i)
		}
		return b.String() + "}\n"
	}, 500)
	linear(t, "Rust unsafe blocks", "a.rs", func(n int) string {
		var b strings.Builder
		b.WriteString("pub fn f(p: *mut i32) {\n")
		for i := range n {
			fmt.Fprintf(&b, "    // SAFETY: p is valid, line %d\n    unsafe { *p = %d; }\n", i, i)
		}
		return b.String() + "}\n"
	}, 4000)
	linear(t, "C++ class chain", "a.cpp", func(n int) string {
		var b strings.Builder
		b.WriteString("class C0 { public: virtual void f(); };\n")
		for i := 1; i < n; i++ {
			fmt.Fprintf(&b, "class C%d : public C%d { public: void f() override; void g%d(); };\n", i, i-1, i)
		}
		return b.String()
	}, 2000)
}

// Shapes that stress tree walks, in every language: deep nesting, a long call
// chain, and many siblings.
func TestHostileShapesStayLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	shapes := map[string]struct {
		gen func(n int) string
		n   int
	}{
		"nesting":  {func(n int) string { return "x = " + strings.Repeat("f(", n) + "1" + strings.Repeat(")", n) + "\n" }, 300},
		"chain":    {func(n int) string { return "x" + strings.Repeat(".a()", n) + "\n" }, 2000},
		"siblings": {func(n int) string { return strings.Repeat("a(1);\n", n) }, 5000},
	}
	for _, ext := range extensions {
		for name, s := range shapes {
			linear(t, ext+" "+name, "src/a"+ext, s.gen, s.n)
		}
	}
}
