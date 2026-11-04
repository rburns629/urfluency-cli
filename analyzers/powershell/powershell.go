// Package powershell analyzes PowerShell scripts and modules with tree-sitter.
// It parses files and never runs them.
package powershell

import (
	"context"
	"strconv"
	"strings"

	ts "github.com/tree-sitter/go-tree-sitter"

	"github.com/rburns629/urfluency-cli/analysis"
	"github.com/rburns629/urfluency-cli/parsing"
)

func init() { analysis.Register(Analyzer{}) }

// Analyzer implements analysis.Analyzer for PowerShell.
type Analyzer struct{}

func (Analyzer) Language() string     { return "powershell" }
func (Analyzer) Extensions() []string { return []string{".ps1", ".psm1"} }

// Skip excludes files that carry a generator header.
func (Analyzer) Skip(f analysis.File) bool {
	return parsing.GeneratedHeader(f.Content)
}

// Complexity is the cognitive complexity syntax for the PowerShell grammar.
// Script blocks such as ForEach-Object { } count as nested functions. The
// grammar nests -and and -or without an operator node, so logical operator
// sequences are not counted.
var Complexity = parsing.ComplexitySyntax{
	Functions: kinds("function_statement", "script_block_expression"),
	Structures: kinds("if_statement", "foreach_statement", "for_statement", "while_statement", "do_statement",
		"switch_statement", "catch_clause", "trap_statement"),
	Hybrids: kinds("elseif_clause", "else_clause"),
}

func kinds(ks ...string) map[string]bool {
	m := make(map[string]bool, len(ks))
	for _, k := range ks {
		m[k] = true
	}
	return m
}

// Analyze applies every PowerShell rule to each file.
func (Analyzer) Analyze(ctx context.Context, files []analysis.File) ([]analysis.Finding, error) {
	var findings []analysis.Finding
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		tree, err := parsing.Parse(parsing.PowerShell, f.Content)
		if err != nil {
			continue
		}
		c := checker{tree: tree, path: f.Path, arrays: map[string]bool{}, grown: map[string]bool{}}
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
	findings []analysis.Finding
	// arrays are the variables set to @(), keyed by function and name, and
	// grown are those already reported as grown in a loop.
	arrays, grown map[string]bool
}

func (c *checker) report(rule string, n *ts.Node) {
	c.findings = append(c.findings, analysis.Finding{Rule: rule, Path: c.path, Line: parsing.Line(n)})
}

// aliases are cmdlet aliases on every platform, lowercased. Names such as ls,
// cp, rm, cat, curl, sleep, sort, write, and rmdir are left out: on Linux and
// macOS they run the native programs (Microsoft's "PowerShell differences on
// non-Windows platforms"). iex has its own rule.
var aliases = map[string]bool{
	"%": true, "?": true, "foreach": true, "where": true, "select": true, "group": true, "measure": true,
	"gci": true, "dir": true, "gc": true, "type": true, "gi": true, "gp": true, "ii": true, "copy": true, "move": true,
	"del": true, "erase": true, "ri": true, "echo": true, "iwr": true, "irm": true,
	"ft": true, "fl": true, "gm": true, "sls": true, "cls": true, "gps": true, "gsv": true, "icm": true,
}

func (c *checker) visit(n *ts.Node) bool {
	switch n.Kind() {
	case "command":
		c.checkCommand(n)
	case "command_parameter":
		if strings.EqualFold(c.tree.Text(n), "-SkipCertificateCheck") {
			c.report("powershell.skip-certificate-check", n)
		}
	case "assignment_expression":
		left := n.NamedChild(0)
		if left == nil {
			break
		}
		lt := strings.ToLower(c.tree.Text(left))
		c.checkArrayGrowth(n, lt)
		switch {
		case strings.HasPrefix(lt, "$global:") && !analysis.IsTestPath(c.path):
			c.report("powershell.global-variable", n)
		case strings.HasSuffix(lt, "servercertificatevalidationcallback") && strings.Contains(strings.ToLower(c.tree.Text(n)), "$true"):
			c.report("powershell.skip-certificate-check", n)
		}
	case "catch_clause":
		if block := lastNamed(n); block != nil && block.Kind() == "statement_block" && block.NamedChildCount() == 0 {
			if !analysis.IsTestPath(c.path) { // tests catch errors on purpose (D-4)
				c.report("powershell.empty-catch", n)
			}
		}
	}
	return true
}

// checkArrayGrowth flags $list += $item in a loop on a variable set to @():
// arrays have a fixed size, so each += copies the whole array, and the loop
// takes time proportional to the square of the item count.
func (c *checker) checkArrayGrowth(n *ts.Node, name string) {
	op := n.ChildByFieldName("operator")
	if op == nil {
		for _, ch := range parsing.NamedChildren(n) {
			if ch.Kind() == "assignement_operator" {
				op = ch
			}
		}
	}
	value := n.ChildByFieldName("value")
	if op == nil || value == nil || !strings.HasPrefix(name, "$") || strings.ContainsAny(name, ".[") {
		return
	}
	fn, inLoop := c.scope(n)
	key := strings.Join([]string{fn, name}, " ")
	switch c.tree.Text(op) {
	case "=":
		if strings.ReplaceAll(c.tree.Text(value), " ", "") == "@()" {
			c.arrays[key] = true
		}
	case "+=":
		if c.arrays[key] && inLoop && !c.grown[key] && !analysis.IsTestPath(c.path) {
			c.grown[key] = true
			c.report("powershell.array-append-in-loop", n)
		}
	}
}

// scope returns where an assignment is: the start of its enclosing function
// ("" at script level) and whether a loop or a ForEach-Object block in that
// function encloses it.
func (c *checker) scope(n *ts.Node) (string, bool) {
	inLoop := false
	for p := c.tree.Parent(n); p != nil; p = c.tree.Parent(p) {
		switch p.Kind() {
		case "foreach_statement", "for_statement", "while_statement", "do_statement":
			inLoop = true
		case "command":
			// Get-Item * | ForEach-Object { $list += $_ }
			name := strings.ToLower(c.commandName(p))
			inLoop = inLoop || name == "foreach-object" || name == "%" || name == "foreach"
		case "function_statement":
			return strconv.Itoa(int(p.StartByte())), inLoop
		}
	}
	return "", inLoop
}

func (c *checker) checkCommand(n *ts.Node) {
	name := strings.ToLower(c.commandName(n))
	switch {
	case (name == "invoke-expression" || name == "iex") && !analysis.IsTestPath(c.path):
		c.report("powershell.invoke-expression", n)
	case aliases[name]:
		c.report("powershell.cmdlet-alias", n)
	case name == "convertto-securestring":
		plain, literal := false, false
		for _, e := range c.elements(n) {
			switch {
			case e.Kind() == "command_parameter" && strings.EqualFold(c.tree.Text(e), "-AsPlainText"):
				plain = true
			case e.Kind() == "array_literal_expression" && isStringLiteral(e):
				literal = true
			}
		}
		if plain && literal {
			c.report("powershell.plaintext-secure-string", n)
		}
	}
}

// commandName returns a command's name as written, or "" for a computed one.
func (c *checker) commandName(n *ts.Node) string {
	if name := n.ChildByFieldName("command_name"); name != nil {
		return c.tree.Text(name)
	}
	return ""
}

// elements returns a command's parameters and arguments.
func (c *checker) elements(n *ts.Node) []*ts.Node {
	if els := n.ChildByFieldName("command_elements"); els != nil {
		return parsing.NamedChildren(els)
	}
	return nil
}

// isStringLiteral reports whether an argument is only a string literal.
func isStringLiteral(n *ts.Node) bool {
	for n.NamedChildCount() == 1 && n.Kind() != "string_literal" {
		n = n.NamedChild(0)
	}
	return n.Kind() == "string_literal"
}

func lastNamed(n *ts.Node) *ts.Node {
	if k := n.NamedChildCount(); k > 0 {
		return n.NamedChild(k - 1)
	}
	return nil
}
