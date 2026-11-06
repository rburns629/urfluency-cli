package javascript

import (
	"context"
	"strings"
	"testing"

	"github.com/rburns629/urfluency-cli/analysis"
	"github.com/rburns629/urfluency-cli/rules"
)

func idioms(t *testing.T, a analysis.Analyzer, path, src string) map[string]int {
	t.Helper()
	findings, err := a.Analyze(context.Background(), []analysis.File{{Path: path, Content: []byte(src)}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, f := range findings {
		if f.Positive && !strings.HasPrefix(f.Rule, "evidence.") {
			got[f.Rule]++
			if r, ok := rules.Lookup(f.Rule); !ok || r.Category != rules.Idiom {
				t.Errorf("%s is not an idiom in the catalog", f.Rule)
			}
		}
	}
	return got
}

func TestIdioms(t *testing.T) {
	js := `async function load(api, ids) {
  const { data } = await api.get("/users");
  const [first] = data;
  const results = await Promise.all(ids.map((id) => api.get(id)));
  return first?.name ?? results.length;
}
`
	got := idioms(t, JavaScript{}, "load.js", js)
	for rule, n := range map[string]int{
		"js.idiom.async-await": 2, "js.idiom.destructuring": 2, "js.idiom.concurrent-promises": 1,
		"js.idiom.optional-chaining": 1, "js.idiom.nullish-coalescing": 1,
	} {
		if got[rule] != n {
			t.Errorf("js %s = %d, want %d", rule, got[rule], n)
		}
	}

	tsSrc := `interface User { id: string; name?: string }
type Status = "active" | "disabled" | "pending";
function isUser(x: unknown): x is User { return typeof x === "object" && x !== null; }
function first<T>(items: T[]): T | undefined { return items[0]; }
type Patch = Partial<User>;
`
	got = idioms(t, TypeScript{}, "user.ts", tsSrc)
	for rule, n := range map[string]int{
		"ts.idiom.declared-types": 3, "ts.idiom.union-types": 2, "ts.idiom.type-guard": 1,
		"ts.idiom.unknown": 1, "ts.idiom.generics": 1, "ts.idiom.utility-types": 1,
	} {
		if got[rule] != n {
			t.Errorf("ts %s = %d, want %d", rule, got[rule], n)
		}
	}
}

func TestConstructs(t *testing.T) {
	js := `function* ids() { yield 1 }
const gen = function* () { yield 2 }
class Bag {
  *[Symbol.iterator]() { yield 3 }
  size() { return 0 }
}
const p = new Proxy({}, { get: (t, k) => Reflect.get(t, k) })
const q = new Map()
function Legacy() {}
Legacy.prototype.run = function () {}
Object.defineProperty(Legacy, "name", { value: "L" })
const keys = Object.keys(q)
class Box {
  get size() { return 0 }
}
`
	ts := `type Unwrap<T> = T extends Promise<infer U> ? U : T
type ReadonlyAll<T> = { readonly [K in keyof T]: T[K] }
type Route = ` + "`/${string}`" + `
type Plain = { a: string }
`
	got := map[string]int{}
	for path, src := range map[string]string{"a.js": js, "b.ts": ts} {
		var a analysis.Analyzer = JavaScript{}
		if strings.HasSuffix(path, ".ts") {
			a = TypeScript{}
		}
		findings, err := a.Analyze(context.Background(), []analysis.File{{Path: path, Content: []byte(src)}})
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range findings {
			if strings.Contains(f.Rule, ".construct.") {
				got[f.Rule]++
			}
		}
	}
	// Prototype assignment, defineProperty, and a getter; not Object.keys.
	want := map[string]int{"js.construct.generators": 3, "js.construct.metaprogramming": 2, "ts.construct.type-level": 3, "js.construct.object-model": 3}
	for rule, n := range want {
		if got[rule] != n {
			t.Errorf("%s = %d, want %d", rule, got[rule], n)
		}
		if r, ok := rules.Lookup(rule); !ok || r.Category != rules.Construct || r.Level() != rules.Advanced {
			t.Errorf("%s is not an advanced construct", rule)
		}
	}
}
