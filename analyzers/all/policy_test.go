package all

import (
	"context"
	"strings"
	"testing"

	"github.com/roburns/urfluency-cli/analysis"
	"github.com/roburns/urfluency-cli/parsing"
)

// Test files catch errors on purpose and hold long table-driven functions, so
// no analyzer reports empty catches or complexity in them (decision D-4).
func TestTestFilesAreExemptFromEmptyCatchAndComplexity(t *testing.T) {
	emptyCatch := map[string]string{
		"src/test/A.java":    "class A { void f() { try { g(); } catch (Exception e) { } } }\n",
		"Tests/A.cs":         "class A { void F() { try { G(); } catch (Exception) { } } }\n",
		"src/a.test.js":      "try { g(); } catch (e) { }\n",
		"src/a.test.ts":      "try { g(); } catch (e) { }\n",
		"tests/test_a.py":    "def f():\n    try:\n        g()\n    except Exception:\n        pass\n",
		"src/test/A.kt":      "fun f() { try { g() } catch (e: Exception) { } }\n",
		"Tests/ATests.swift": "func f() { do { try g() } catch { } }\n",
		"test/a_test.dart":   "void f() { try { g(); } catch (e) { } }\n",
		"tests/a.Tests.ps1":  "try { G } catch { }\n",
		"tests/ATest.php":    "<?php\nfunction f() { try { g(); } catch (Exception $e) { } }\n",
		"spec/a_spec.rb":     "def f\n  g\nrescue StandardError\nend\n",
		"tests/a_test.cpp":   "void f() { try { g(); } catch (...) { } }\n",
	}
	for p, src := range emptyCatch {
		for _, f := range analyze(t, p, src) {
			if strings.Contains(f.Rule, "empty") || strings.Contains(f.Rule, "swallowed") {
				t.Errorf("%s: %s in a test file", p, f.Rule)
			}
		}
	}
	// A deeply nested function, well over the complexity threshold.
	nested := func(open, close string, n int) string { return strings.Repeat(open, n) + strings.Repeat(close, n) }
	complex := map[string]string{
		"tests/a.Tests.ps1": "function F($x) {\n" + nested("if ($x) {\n", "}\n", parsing.CognitiveThreshold) + "}\n",
		"tests/a_test.sh":   "f() {\n" + nested("if true; then\n", "fi\n", parsing.CognitiveThreshold) + "}\n",
	}
	for p, src := range complex {
		for _, f := range analyze(t, p, src) {
			if f.Rule == "clean.cognitive-complexity" {
				t.Errorf("%s: complexity reported in a test file", p)
			}
		}
		if p := strings.Replace(p, "tests/", "src/", 1); !hasRule(analyze(t, strings.Replace(strings.Replace(p, ".Tests", "", 1), "_test", "", 1), src), "clean.cognitive-complexity") {
			t.Errorf("%s: the same function outside tests is not reported, so the case checks nothing", p)
		}
	}
}

func analyze(t *testing.T, path, src string) []analysis.Finding {
	t.Helper()
	a := analysis.ForPath(path)
	if a == nil {
		t.Fatalf("no analyzer for %s", path)
	}
	fs, err := a.Analyze(context.Background(), []analysis.File{{Path: path, Content: []byte(src)}})
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func hasRule(fs []analysis.Finding, rule string) bool {
	for _, f := range fs {
		if f.Rule == rule {
			return true
		}
	}
	return false
}
