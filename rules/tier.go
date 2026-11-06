package rules

// Tier places a rule on the path from learning a language to commanding it,
// for the level (DESIGN.md, "Levels from evidence").
//
// A problem is Fundamental when it shows a misunderstanding of how the
// language works, such as a bare except or a mutable default argument;
// Practice, the default, when it is a habit or judgment; and Advanced when
// only an advanced feature can produce it, such as a __getattr__ that never
// raises AttributeError. An idiom or construct is Basic, the default,
// Intermediate, or Advanced, by what using it shows.
type Tier string

const (
	Fundamental  Tier = "fundamental"
	Practice     Tier = "practice"
	Basic        Tier = "basic"
	Intermediate Tier = "intermediate"
	Advanced     Tier = "advanced"
)

// Level is the rule's tier with the defaults filled in.
func (r Rule) Level() Tier {
	switch {
	case r.Tier != "":
		return r.Tier
	case r.Category.Positive():
		return Basic
	}
	return Practice
}

// tiers are the tiers of this catalog's rules. Rules registered elsewhere,
// such as the engine's, set Tier themselves.
var tiers = map[string]Tier{
	// Python mistakes that show a misunderstanding of the language. A bare
	// except, a swallowed exception, and a mutable default are practice:
	// Flask and SQLAlchemy catch everything to clean up and re-raise, and
	// accelerate passes [] defaults it never changes, on purpose.
	"py.is-literal-comparison": Fundamental,

	// Python idioms.
	"py.idiom.f-string":         Basic,
	"py.idiom.context-manager":  Basic,
	"py.idiom.pathlib":          Basic,
	"py.idiom.type-hints":       Intermediate,
	"py.idiom.structured-data":  Intermediate,
	"py.idiom.comprehension":    Intermediate,
	"py.idiom.generator":        Intermediate,
	"py.idiom.custom-exception": Intermediate,
	"py.idiom.pytest":           Intermediate,
	// async def is the shape frameworks such as FastAPI and discord.py ask
	// for, so writing it shows familiarity, not command.
	"py.idiom.async":    Intermediate,
	"py.idiom.protocol": Advanced,

	// Go mistakes that show a misunderstanding of the language: a discarded
	// Sprintf or errors.New. An empty switch case is practice: Gitea, Caddy,
	// and restic write case io.SeekStart: to do nothing, on purpose.
	"go.discarded-result": Fundamental,
	// Go mistakes possible only with goroutines and channels.
	"go.waitgroup-add-before-conditional-launch": Advanced,
	"go.waitgroup-add-in-goroutine":              Advanced,
	"go.waitgroup-done-not-deferred":             Advanced,
	"go.goroutine-send-leak":                     Advanced,

	// Go idioms.
	"go.idiom.defer-cleanup":          Basic,
	"go.idiom.error-wrapping":         Intermediate,
	"go.idiom.error-inspection":       Intermediate,
	"go.idiom.custom-error-type":      Intermediate,
	"go.idiom.context-first":          Intermediate,
	"go.idiom.small-interface":        Intermediate,
	"go.idiom.table-driven-test":      Intermediate,
	"go.idiom.cancellation":           Advanced,
	"go.idiom.structured-concurrency": Advanced,
	"go.idiom.generics":               Advanced,

	// Go constructs.
	"go.construct.channels":   Advanced,
	"go.construct.sync":       Advanced,
	"go.construct.iterators":  Advanced,
	"go.construct.reflection": Advanced,

	// JavaScript's loose equality and empty catch are practice: socket.io
	// writes typeof x == "string" and zod catches feature checks on
	// purpose.

	// JavaScript and TypeScript idioms.
	"js.idiom.optional-chaining":   Basic,
	"js.idiom.nullish-coalescing":  Basic,
	"js.idiom.destructuring":       Basic,
	"js.idiom.async-await":         Intermediate,
	"js.idiom.concurrent-promises": Advanced,
	"ts.idiom.declared-types":      Basic,
	"ts.idiom.union-types":         Intermediate,
	"ts.idiom.unknown":             Intermediate,
	"ts.idiom.utility-types":       Intermediate,
	"ts.idiom.generics":            Advanced,
	"ts.idiom.type-guard":          Advanced,

	// JavaScript and TypeScript constructs.
	"js.construct.generators":      Advanced,
	"js.construct.metaprogramming": Advanced,
	"js.construct.object-model":    Advanced,
	"ts.construct.type-level":      Advanced,

	// Other languages' tiers, audited 2026-11-06: their existing rules are
	// practice unless listed, and their idioms are tiered by what using
	// them shows.
	"java.string-equality":                  Fundamental,
	"csharp.async-void":                     Advanced,
	"csharp.blocking-on-task":               Advanced,
	"kotlin.global-scope":                   Advanced,
	"kotlin.run-blocking-in-production":     Advanced,
	"ruby.core-class-reopened":              Advanced,
	"c.idiom.bounded-string":                Basic,
	"c.idiom.sizeof-object":                 Intermediate,
	"c.idiom.const-pointer-param":           Intermediate,
	"c.idiom.static-function":               Basic,
	"c.idiom.designated-initializer":        Intermediate,
	"c.idiom.enum-constants":                Basic,
	"c.idiom.goto-cleanup":                  Advanced,
	"c.idiom.include-guard":                 Basic,
	"c.idiom.static-assert":                 Advanced,
	"c.idiom.fixed-width-types":             Basic,
	"csharp.idiom.async-await":              Intermediate,
	"csharp.idiom.linq":                     Intermediate,
	"csharp.idiom.using-disposal":           Basic,
	"csharp.idiom.records":                  Intermediate,
	"csharp.idiom.pattern-matching":         Advanced,
	"csharp.idiom.nullable-annotations":     Intermediate,
	"csharp.idiom.expression-bodied":        Basic,
	"csharp.idiom.init-only":                Intermediate,
	"csharp.idiom.cancellation-token":       Advanced,
	"cpp.idiom.smart-pointers":              Intermediate,
	"cpp.idiom.range-for":                   Basic,
	"cpp.idiom.constexpr":                   Advanced,
	"cpp.idiom.move-semantics":              Advanced,
	"cpp.idiom.lambda":                      Intermediate,
	"cpp.idiom.override":                    Basic,
	"cpp.idiom.templates":                   Advanced,
	"cpp.idiom.vocabulary-types":            Intermediate,
	"cpp.idiom.raii-lock":                   Intermediate,
	"cpp.idiom.structured-bindings":         Intermediate,
	"dart.idiom.null-aware":                 Basic,
	"dart.idiom.async-await":                Intermediate,
	"dart.idiom.generator":                  Advanced,
	"dart.idiom.const-constructor":          Intermediate,
	"dart.idiom.required-named-parameters":  Basic,
	"dart.idiom.extension-methods":          Advanced,
	"dart.idiom.sealed-class":               Advanced,
	"dart.idiom.pattern-matching":           Advanced,
	"dart.idiom.records":                    Intermediate,
	"dart.idiom.collection-control-flow":    Intermediate,
	"kotlin.idiom.data-class":               Basic,
	"kotlin.idiom.sealed-hierarchy":         Advanced,
	"kotlin.idiom.exhaustive-when":          Intermediate,
	"kotlin.idiom.null-safety":              Basic,
	"kotlin.idiom.extension-function":       Intermediate,
	"kotlin.idiom.suspend-function":         Intermediate,
	"kotlin.idiom.structured-concurrency":   Advanced,
	"kotlin.idiom.scope-function":           Intermediate,
	"kotlin.idiom.collection-operations":    Intermediate,
	"kotlin.idiom.reified-generics":         Advanced,
	"php.idiom.strict-types":                Intermediate,
	"php.idiom.typed-property":              Intermediate,
	"php.idiom.constructor-promotion":       Intermediate,
	"php.idiom.readonly":                    Intermediate,
	"php.idiom.enum":                        Intermediate,
	"php.idiom.match":                       Intermediate,
	"php.idiom.nullsafe-operator":           Basic,
	"php.idiom.named-arguments":             Basic,
	"php.idiom.first-class-callable":        Advanced,
	"php.idiom.prepared-statement":          Basic,
	"rust.idiom.question-mark":              Basic,
	"rust.idiom.result-return":              Basic,
	"rust.idiom.iterator-chain":             Intermediate,
	"rust.idiom.enum-match":                 Basic,
	"rust.idiom.traits":                     Intermediate,
	"rust.idiom.trait-bounds":               Advanced,
	"rust.idiom.combinators":                Intermediate,
	"rust.idiom.test-module":                Basic,
	"rust.idiom.error-type":                 Intermediate,
	"rust.idiom.lifetimes":                  Advanced,
	"java.idiom.try-with-resources":         Basic,
	"java.idiom.streams":                    Intermediate,
	"java.idiom.optional":                   Intermediate,
	"java.idiom.records":                    Intermediate,
	"java.idiom.var":                        Basic,
	"java.idiom.switch-expression":          Intermediate,
	"java.idiom.lambdas":                    Intermediate,
	"java.idiom.bounded-generics":           Advanced,
	"java.idiom.sealed-types":               Advanced,
	"java.idiom.pattern-matching":           Advanced,
	"powershell.idiom.advanced-function":    Intermediate,
	"powershell.idiom.comment-based-help":   Basic,
	"powershell.idiom.parameter-validation": Intermediate,
	"powershell.idiom.pipeline-input":       Advanced,
	"powershell.idiom.should-process":       Advanced,
	"powershell.idiom.splatting":            Intermediate,
	"powershell.idiom.strict-mode":          Basic,
	"powershell.idiom.typed-parameters":     Basic,
	"ruby.idiom.comparable-enumerable":      Advanced,
	"ruby.idiom.endless-method":             Intermediate,
	"ruby.idiom.enumerable-methods":         Intermediate,
	"ruby.idiom.frozen-string-literal":      Basic,
	"ruby.idiom.guard-clause":               Basic,
	"ruby.idiom.keyword-arguments":          Basic,
	"ruby.idiom.pattern-matching":           Advanced,
	"ruby.idiom.safe-navigation":            Basic,
	"ruby.idiom.value-object":               Intermediate,
	"ruby.idiom.yield-block":                Intermediate,
	"shell.idiom.arrays":                    Intermediate,
	"shell.idiom.double-brackets":           Basic,
	"shell.idiom.getopts":                   Intermediate,
	"shell.idiom.local-variables":           Basic,
	"shell.idiom.main-function":             Basic,
	"shell.idiom.parameter-defaults":        Intermediate,
	"shell.idiom.read-raw":                  Basic,
	"shell.idiom.strict-mode":               Basic,
	"shell.idiom.trap-cleanup":              Advanced,
	"swift.idiom.actor-isolation":           Advanced,
	"swift.idiom.associated-values":         Intermediate,
	"swift.idiom.async-await":               Intermediate,
	"swift.idiom.codable":                   Intermediate,
	"swift.idiom.constrained-generics":      Advanced,
	"swift.idiom.defer":                     Basic,
	"swift.idiom.guard-early-exit":          Basic,
	"swift.idiom.property-wrapper":          Advanced,
	"swift.idiom.protocol-extension":        Advanced,
	"swift.idiom.value-type":                Basic,

	// Constructs of Ruby, Shell, PHP, C, and Java.
	"ruby.construct.metaprogramming":  Advanced,
	"shell.construct.expansion":       Advanced,
	"php.construct.traits":            Advanced,
	"php.construct.generators":        Advanced,
	"php.construct.metaprogramming":   Advanced,
	"c.construct.function-pointers":   Advanced,
	"c.construct.variadic":            Advanced,
	"c.construct.memory-layout":       Advanced,
	"java.construct.generic-types":    Advanced,
	"java.construct.concurrency":      Advanced,
	"java.construct.reflection":       Advanced,
	"java.construct.annotation-types": Advanced,

	// Python constructs.
	"py.construct.protocol-methods":     Advanced,
	"py.construct.decorator-definition": Advanced,
	"py.construct.metaprogramming":      Advanced,
	"py.construct.generic-typing":       Advanced,
}
