// Package gates names the quality gates of clean-agent-code's QUALITY_GATES.md
// and recognizes commands that run them, in CI configuration and in the commands
// coding agents run.
package gates

import (
	"regexp"
	"slices"
	"sort"
)

// Gates, in report order.
const (
	Format   = "format"
	Lint     = "lint"
	Types    = "types"
	Build    = "build"
	Tests    = "tests"
	Security = "security" // dependency vulnerability, secret, and security scans
	Other    = "other"    // a check that delegates to an unknown target, such as "make check"
)

var (
	mandatory = []string{Format, Lint, Types, Build, Tests}
	named     = []string{Format, Lint, Types, Build, Tests, Security}
	// all is named plus Other, the order of Set bits.
	all = append(slices.Clone(named), Other)
)

// Mandatory returns the gates that apply to every change where the language
// supports them; Security is conditional on the change. The list is a copy,
// so a caller cannot change it for others.
func Mandatory() []string { return slices.Clone(mandatory) }

// Named returns every gate except Other, as a copy.
func Named() []string { return slices.Clone(named) }

// Set is a compact, comparable set of gates.
type Set uint8

// With returns the set plus the named gates.
func (s Set) With(names ...string) Set {
	for _, n := range names {
		for i, g := range all {
			if g == n {
				s |= 1 << i
			}
		}
	}
	return s
}

// Has reports whether the set includes a gate.
func (s Set) Has(name string) bool {
	for i, g := range all {
		if g == name {
			return s&(1<<i) != 0
		}
	}
	return false
}

// Standard is the clean-agent-code document that defines the gates.
const Standard = "https://github.com/roburns/clean-agent-code/blob/main/standards/QUALITY_GATES.md"

var patterns = []struct {
	gate string
	re   *regexp.Regexp
}{
	{Format, regexp.MustCompile(`\b(gofmt|goimports|prettier|black|ruff format|cargo fmt|rustfmt|clang-format|dotnet format|google-java-format|spotless(Apply|Check)|ktfmt|swiftformat|swift-format|dart format|flutter format|shfmt)\b`)},
	{Lint, regexp.MustCompile(`\b(golangci-lint|staticcheck|go vet|eslint|ruff check|flake8|pylint|clippy|clang-tidy|cppcheck|checkstyle|spotbugs|pmd|ktlint|detekt|swiftlint|dart analyze|flutter analyze|shellcheck|Invoke-ScriptAnalyzer|(npm|pnpm|yarn|bun)( run)? lint|make lint)\b`)},
	{Types, regexp.MustCompile(`\b(tsc|mypy|pyright|cargo check|(npm|pnpm|yarn|bun)( run)? (typecheck|type-check))\b`)},
	{Build, regexp.MustCompile(`\b(go build|cargo build|cmake --build|msbuild|mvn (package|compile|verify|install)|(gradle|gradlew) (build|assemble)|dotnet build|swift build|xcodebuild( build)?|flutter build|(npm|pnpm|yarn|bun)( run)? build|make build)\b`)},
	{Tests, regexp.MustCompile(`\b(go test|pytest|python -m unittest|vitest|jest|cargo (test|nextest)|ctest|mvn (test|verify)|(gradle|gradlew) (test|check)|dotnet test|swift test|xcodebuild test|flutter test|dart test|bats|Invoke-Pester|(npm|pnpm|yarn|bun)( run)? test|make test)\b`)},
	{Security, regexp.MustCompile(`\b(govulncheck|npm audit|pnpm audit|yarn audit|pip-audit|cargo (audit|deny)|dependency-check|dotnet list package --vulnerable|codeql|semgrep|gitleaks|trivy|snyk|osv-scanner)\b`)},
}

// delegated targets run some checks without naming which.
var delegated = regexp.MustCompile(`\b(make|just|task) (check|verify|ci)\b|\b(npm|pnpm|yarn)( run)? (check|verify|ci)\b`)

// installLine matches lines that install tools rather than run them, such as
// pip install black mypy pytest.
var installLine = regexp.MustCompile(`\b(pip3? install|python3? -m pip install|uv (pip install|add|tool install)|pipx install|poetry add|npm (i|install|add|ci)|yarn (add|global add)|pnpm (add|i|install)|bun (add|install)|npx --yes install|go install|cargo (install|binstall)|gem install|brew install|apt(-get)? install|apk add|dnf install|yum install|choco install|dotnet tool (install|restore)|Install-Module)\b`)

// commandBreak separates commands: lines, and a; b, a && b, a || b, and a | b
// within one.
var commandBreak = regexp.MustCompile(`\n|&&|\|\|?|;`)

// fileName matches what follows a tool's name when the text names a file,
// such as jest.config.js or mypy.ini.
var fileName = regexp.MustCompile(`^\.[A-Za-z]`)

// Run returns the gates that text runs, in Named order, with Other when it only
// delegates to an unknown check target. Commands that install tools, as in
// pip install pytest && pytest, and tool names that are part of a file name,
// do not count.
func Run(text string) []string {
	ran := map[string]bool{}
	delegates := false
	for _, line := range commandBreak.Split(text, -1) {
		if installLine.MatchString(line) {
			continue
		}
		for _, p := range patterns {
			for _, m := range p.re.FindAllStringIndex(line, -1) {
				if !fileName.MatchString(line[m[1]:]) {
					ran[p.gate] = true
				}
			}
		}
		delegates = delegates || delegated.MatchString(line)
	}
	var out []string
	for _, p := range patterns {
		if ran[p.gate] {
			out = append(out, p.gate)
		}
	}
	if len(out) == 0 && delegates {
		out = append(out, Other)
	}
	return out
}

// compilingLinters type-check the language they lint: go vet, golangci-lint,
// and staticcheck load Go packages, clippy compiles Rust, the Dart analyzer
// type-checks, and clang-tidy runs the compiler's front end. Linters such as
// swiftlint, ktlint, detekt, checkstyle, and cppcheck do not.
var compilingLinters = map[string]*regexp.Regexp{
	"go":   regexp.MustCompile(`\b(go vet|golangci-lint|staticcheck)\b`),
	"rust": regexp.MustCompile(`\bclippy\b`),
	"dart": regexp.MustCompile(`\b(dart|flutter) analyze\b`),
	"c":    regexp.MustCompile(`\bclang-tidy\b`),
	"cpp":  regexp.MustCompile(`\bclang-tidy\b`),
}

// TypeChecked returns the languages that a lint tool in text type-checks.
func TypeChecked(text string) []string {
	var out []string
	for language, re := range compilingLinters {
		if re.MatchString(text) {
			out = append(out, language)
		}
	}
	sort.Strings(out)
	return out
}

// compiled languages type-check when they build.
var compiled = map[string]bool{"go": true, "rust": true, "c": true, "cpp": true, "csharp": true, "java": true,
	"kotlin": true, "swift": true, "dart": true}

// Applies reports whether a mandatory gate applies to a language: type checking
// and build apply where the language has them (compiled languages and
// TypeScript); format, lint, and tests apply everywhere.
func Applies(gate, language string) bool {
	switch gate {
	case Types, Build:
		return compiled[language] || language == "typescript"
	}
	return true
}

// Implied returns the gates a language satisfies through others: building a
// compiled language type-checks it, and so do its test tools (go test, cargo
// test, mvn test, and so on) and, when lintCompiles, its lint tool (see
// TypeChecked).
func Implied(language string, ran map[string]bool, lintCompiles bool) map[string]bool {
	out := map[string]bool{}
	for g := range ran {
		out[g] = true
	}
	if compiled[language] && (ran[Tests] || ran[Build] || (ran[Lint] && lintCompiles)) {
		out[Types], out[Build] = true, true
	}
	return out
}
