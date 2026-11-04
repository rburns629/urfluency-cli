// Package shell analyzes Bash and POSIX sh scripts with tree-sitter. It parses
// scripts and never runs them.
package shell

import (
	"bytes"
	"context"
	"path"
	"regexp"
	"strings"

	ts "github.com/tree-sitter/go-tree-sitter"

	"github.com/rburns629/urfluency-cli/analysis"
	"github.com/rburns629/urfluency-cli/parsing"
)

func init() { analysis.Register(Analyzer{}) }

// Analyzer implements analysis.Analyzer for shell scripts.
type Analyzer struct{}

func (Analyzer) Language() string     { return "shell" }
func (Analyzer) Extensions() []string { return []string{".sh", ".bash"} }

// generatedNames are scripts tools write, such as Flutter's environment export.
var generatedNames = map[string]bool{"flutter_export_environment.sh": true, "install-sh": true}

// SkipPath excludes generated scripts.
func (Analyzer) SkipPath(p string) bool { return generatedNames[path.Base(p)] }

// Skip also excludes scripts that carry a generator header.
func (a Analyzer) Skip(f analysis.File) bool {
	if a.SkipPath(f.Path) {
		return true
	}
	return parsing.GeneratedHeader(f.Content)
}

// Complexity is the cognitive complexity syntax for the Bash grammar. && and ||
// count inside [[ ]] tests; between commands they are list nodes without an
// operator field, so they are not counted.
var Complexity = parsing.ComplexitySyntax{
	Functions:  kinds("function_definition"),
	Structures: kinds("if_statement", "for_statement", "c_style_for_statement", "while_statement", "case_statement"),
	Hybrids:    kinds("elif_clause", "else_clause"),
	Logical:    "binary_expression",
	LogicalOps: kinds("&&", "||"),
}

func kinds(ks ...string) map[string]bool {
	m := make(map[string]bool, len(ks))
	for _, k := range ks {
		m[k] = true
	}
	return m
}

// Analyze applies every shell rule to each file.
func (Analyzer) Analyze(ctx context.Context, files []analysis.File) ([]analysis.Finding, error) {
	var findings []analysis.Finding
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		tree, err := parsing.Parse(parsing.Bash, f.Content)
		if err != nil {
			continue
		}
		c := checker{tree: tree, path: f.Path, errexit: hasErrexit(tree), zsh: isZsh(f.Path, f.Content)}
		if bytes.HasPrefix(f.Content, []byte("#!")) && !c.errexit && !analysis.IsTestPath(f.Path) {
			c.findings = append(c.findings, analysis.Finding{Rule: "shell.missing-errexit", Path: f.Path, Line: 1})
		}
		parsing.Walk(tree.Root(), c.visit)
		parsing.Walk(tree.Root(), c.visitIdioms)
		for _, fn := range parsing.Cognitive(tree, Complexity) {
			if !analysis.IsTestPath(f.Path) {
				c.findings = append(c.findings, analysis.EvidenceOf(f.Path, fn.Line, fn.Complexity)...)
			}
			if fn.Complexity > parsing.CognitiveThreshold && !analysis.IsTestPath(f.Path) {
				c.findings = append(c.findings, analysis.Finding{Rule: "clean.cognitive-complexity", Path: f.Path, Line: fn.Line})
			}
		}
		tree.Close()
		findings = append(findings, c.findings...)
	}
	return findings, nil
}

type checker struct {
	tree     *parsing.Tree
	path     string
	errexit  bool // the script runs with set -e
	zsh      bool // zsh code, which does not split unquoted expansions
	findings []analysis.Finding
}

// zshSyntax matches what only zsh code uses: option, completion, and style
// builtins, emulate, and parameter expansion flags such as ${(j:,:)list}.
var zshSyntax = regexp.MustCompile(`(?m)^\s*(setopt|unsetopt|zstyle|compdef|zle\s|emulate\s+-L\s+zsh|autoload\s+-U)|\$\{\([a-zA-Z@:,]+\)`)

// isZsh reports zsh code: a .zsh file, a zsh shebang, or zsh-only syntax in
// a file zsh sources, such as oh-my-zsh.sh.
func isZsh(path string, content []byte) bool {
	if strings.HasSuffix(path, ".zsh") || strings.HasSuffix(path, ".zsh-theme") {
		return true
	}
	if first, _, _ := bytes.Cut(content, []byte("\n")); bytes.HasPrefix(first, []byte("#!")) {
		return bytes.Contains(first, []byte("zsh"))
	}
	return zshSyntax.Match(content)
}

func (c *checker) report(rule string, n *ts.Node) {
	c.findings = append(c.findings, analysis.Finding{Rule: rule, Path: c.path, Line: parsing.Line(n)})
}

func (c *checker) visit(n *ts.Node) bool {
	switch n.Kind() {
	case "command":
		c.checkCommand(n)
	case "pipeline":
		c.checkPipeline(n)
	case "for_statement":
		if v := n.ChildByFieldName("value"); v != nil && v.Kind() == "command_substitution" && firstCommand(c.tree, v) == "ls" {
			c.report("shell.ls-in-loop", n)
		}
	case "command_substitution":
		if n.ChildCount() > 0 && n.Child(0).Kind() == "`" {
			c.report("shell.backtick-substitution", n)
		}
	}
	return true
}

// specialVariables expand to a single word, so quoting them changes nothing.
var specialVariables = map[string]bool{"$#": true, "$?": true, "$$": true, "$!": true, "$-": true}

// unguardedPath matches a variable followed only by / or /*, as in "$DIR/"
// or "$DIR"/*, which deletes from the root when DIR is empty (ShellCheck
// SC2115). ${DIR:?} stops the script instead.
var unguardedPath = regexp.MustCompile(`^"?\$\{?[A-Za-z_][A-Za-z0-9_]*\}?"?/"?\*?"?$`)

func (c *checker) checkCommand(n *ts.Node) {
	name := commandName(c.tree, n)
	args := arguments(n)
	unquoted := false
	for _, a := range args {
		unquoted = unquoted || c.isUnquotedExpansion(a)
	}
	if unquoted && name != "" && !c.zsh {
		c.report("shell.unquoted-expansion", n)
	}
	switch name {
	case "eval":
		for _, a := range args {
			if hasExpansion(a) {
				c.report("shell.eval", n)
				break
			}
		}
	case "rm":
		recursive := false
		for _, a := range args {
			t := c.tree.Text(a)
			recursive = recursive || t == "--recursive" || (strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--") && strings.ContainsAny(t, "rR"))
		}
		for _, a := range args {
			if recursive && unguardedPath.MatchString(c.tree.Text(a)) {
				c.report("shell.rm-unguarded-path", n)
				break
			}
		}
	case "cd":
		if !c.errexit && !handled(c.tree, n) {
			c.report("shell.cd-unchecked", n)
		}
	case "curl", "wget":
		// Benchmarks, CI, and end-to-end scripts call test servers with
		// self-signed certificates.
		if c.insecureDownload(name, args) && !analysis.IsTestPath(c.path) && !parsing.InDir(c.path, "ci", "e2e", "bench", "benchmarks") {
			c.report("shell.tls-verification-disabled", n)
		}
	}
}

// insecureDownload reports curl -k or --insecure, and wget
// --no-check-certificate, to anything but this machine, where a self-signed
// development certificate is expected.
func (c *checker) insecureDownload(name string, args []*ts.Node) bool {
	insecure := false
	for _, a := range args {
		t := strings.Trim(c.tree.Text(a), `"'`)
		if strings.Contains(t, "localhost") || strings.Contains(t, "127.0.0.1") || strings.Contains(t, "[::1]") {
			return false
		}
		switch {
		case name == "wget":
			insecure = insecure || t == "--no-check-certificate"
		case t == "--insecure":
			insecure = true
		case len(t) > 1 && t[0] == '-' && t[1] != '-' && isShortFlags(t[1:]) && strings.ContainsRune(t[1:], 'k'):
			insecure = true
		}
	}
	return insecure
}

// isShortFlags reports a cluster of single-letter options, such as sSLk.
func isShortFlags(s string) bool {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}

// isUnquotedExpansion reports whether a command argument is, or starts with,
// an expansion outside quotes.
func (c *checker) isUnquotedExpansion(a *ts.Node) bool {
	switch a.Kind() {
	case "simple_expansion", "expansion", "command_substitution":
		t := c.tree.Text(a)
		return !specialVariables[t] && !strings.HasPrefix(t, "${#")
	case "concatenation":
		for _, child := range parsing.NamedChildren(a) {
			if c.isUnquotedExpansion(child) {
				return true
			}
		}
	}
	return false
}

// handled reports whether a command's failure is handled: followed by || or
// && at any level of a list (cd dir || exit; a && cd dir || exit), negated
// with !, or tested as the condition of if, elif, while, or until.
func handled(t *parsing.Tree, n *ts.Node) bool {
	for child, p := n, t.Parent(n); p != nil; child, p = p, t.Parent(p) {
		switch p.Kind() {
		case "list":
			if next := child.NextSibling(); next != nil && (next.Kind() == "||" || next.Kind() == "&&") {
				return true
			}
		case "negated_command":
			return true
		case "if_statement", "elif_clause", "while_statement", "until_statement":
			cond := p.ChildByFieldName("condition")
			return cond != nil && cond.Equals(*child)
		case "program", "compound_statement", "subshell", "function_definition", "do_group":
			return false
		}
	}
	return false
}

var shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true}

// checkPipeline reports curl or wget piped into a shell, including sudo bash.
func (c *checker) checkPipeline(n *ts.Node) {
	downloaded := false
	for _, cmd := range parsing.NamedChildren(n) {
		if cmd.Kind() != "command" {
			continue
		}
		name := commandName(c.tree, cmd)
		if name == "sudo" {
			if args := arguments(cmd); len(args) > 0 {
				name = c.tree.Text(args[0])
			}
		}
		switch {
		case name == "curl" || name == "wget":
			downloaded = true
		case downloaded && shells[path.Base(name)]:
			c.report("shell.pipe-to-shell", n)
			return
		}
	}
}

// commandName returns a command's name, or "" when it is computed.
func commandName(t *parsing.Tree, n *ts.Node) string {
	if name := n.ChildByFieldName("name"); name != nil {
		return t.Text(name)
	}
	return ""
}

// arguments returns a command's arguments.
func arguments(n *ts.Node) []*ts.Node {
	var out []*ts.Node
	for i := uint(0); i < n.ChildCount(); i++ {
		if n.FieldNameForChild(uint32(i)) == "argument" {
			out = append(out, n.Child(i))
		}
	}
	return out
}

// firstCommand returns the name of the first command inside n.
func firstCommand(t *parsing.Tree, n *ts.Node) string {
	name := ""
	parsing.Walk(n, func(m *ts.Node) bool {
		if name == "" && m.Kind() == "command" {
			name = commandName(t, m)
		}
		return name == ""
	})
	return name
}

func hasExpansion(n *ts.Node) bool {
	found := false
	parsing.Walk(n, func(m *ts.Node) bool {
		switch m.Kind() {
		case "simple_expansion", "expansion", "command_substitution":
			found = true
		}
		return !found
	})
	return found
}

// hasErrexit reports whether the script enables set -e (or set -o errexit).
func hasErrexit(t *parsing.Tree) bool {
	found := false
	parsing.Walk(t.Root(), func(n *ts.Node) bool {
		if found || n.Kind() != "command" || commandName(t, n) != "set" {
			return !found
		}
		// Each letter after a single dash is an option, so -e, -eu, and -euo all
		// set errexit.
		args := arguments(n)
		for i, a := range args {
			s := t.Text(a)
			if (strings.HasPrefix(s, "-") && !strings.HasPrefix(s, "--") && strings.Contains(s[1:], "e")) ||
				(s == "-o" && i+1 < len(args) && t.Text(args[i+1]) == "errexit") {
				found = true
			}
		}
		return false
	})
	return found
}
