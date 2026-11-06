package shell

import (
	"regexp"

	ts "github.com/tree-sitter/go-tree-sitter"
)

// advancedExpansion matches parameter expansions that transform a value:
// ${!name} indirection, ${x#p} and ${x%p} trimming, ${x//a/b} substitution,
// ${x^^} and ${x,,} case changes, and ${x:1:2} substrings. Defaults such as
// ${x:-y} are an idiom of their own.
var advancedExpansion = regexp.MustCompile(`^\$\{(!|#?[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?(##?|%%?|//?|\^\^?|,,?|:[0-9]))`)

// visitConstructs records advanced parameter expansion and process
// substitution.
func (c *checker) visitConstructs(n *ts.Node) {
	switch n.Kind() {
	case "expansion":
		if advancedExpansion.MatchString(c.tree.Text(n)) {
			c.idiom("shell.construct.expansion", n)
		}
	case "process_substitution":
		c.idiom("shell.construct.expansion", n)
	}
}
