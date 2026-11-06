package analyzers_test

import (
	"context"
	"strings"
	"testing"

	"github.com/rburns629/urfluency-cli/analysis"
	_ "github.com/rburns629/urfluency-cli/analyzers/all"
	"github.com/rburns629/urfluency-cli/rules"
)

// The constructs of Ruby, Shell, PHP, C, and Java each count what they
// name and not the code that only looks like it.
func TestConstructs(t *testing.T) {
	for _, tc := range []struct {
		path, src string
		want      map[string]int
	}{
		{"lib/a.rb", `class Base
  def self.included(base); end
  def method_missing(name, *args) = super
  def respond_to_missing?(name, all = false) = super
  define_method(:hello) { 1 }
  def plain; send(:x); end
end
`, map[string]int{"ruby.construct.metaprogramming": 4}},
		{"bin/a.sh", `#!/bin/bash
x=${path//\//_}
y=${name#prefix}
z=${!ref}
w=${default:-fallback}
v=$plain
diff <(sort a) <(sort b)
`, map[string]int{"shell.construct.expansion": 5}},
		{"src/A.php", `<?php
trait Greets { public function hi() {} }
class A {
  public function __get($n) { return 1; }
  public function __toString(): string { return ""; }
  public function gen() { yield 1; }
  public function r() { return new \ReflectionClass($this); }
}
`, map[string]int{"php.construct.traits": 1, "php.construct.generators": 1, "php.construct.metaprogramming": 2}},
		{"src/a.c", `#include <stdarg.h>
typedef int (*handler)(int);
int log_all(const char *fmt, ...);
union value { int i; float f; };
struct flags { unsigned ready : 1; };
int call(int (*fn)(int), int x) { return fn(x); }
int plain(int x) { return x; }
`, map[string]int{"c.construct.function-pointers": 2, "c.construct.variadic": 1, "c.construct.memory-layout": 2}},
		{"src/A.java", `import java.util.concurrent.ConcurrentHashMap;
public class A<T> {
  private volatile boolean done;
  private final ConcurrentHashMap<String, T> map = new ConcurrentHashMap<>();
  public synchronized void run() throws Exception { getClass().getDeclaredMethod("x"); }
}
@interface Marker {}
`, map[string]int{"java.construct.generic-types": 1, "java.construct.concurrency": 4, "java.construct.reflection": 1, "java.construct.annotation-types": 1}},
	} {
		a := analysis.ForPath(tc.path)
		findings, err := a.Analyze(context.Background(), []analysis.File{{Path: tc.path, Content: []byte(tc.src)}})
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]int{}
		for _, f := range findings {
			if strings.Contains(f.Rule, ".construct.") {
				got[f.Rule]++
			}
		}
		for rule, n := range tc.want {
			if got[rule] != n {
				t.Errorf("%s: %s = %d, want %d", tc.path, rule, got[rule], n)
			}
			if r, ok := rules.Lookup(rule); !ok || r.Category != rules.Construct || r.Level() != rules.Advanced {
				t.Errorf("%s is not an advanced construct", rule)
			}
		}
	}
}
