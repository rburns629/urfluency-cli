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

	// Go mistakes that show a misunderstanding of the language: an empty
	// case that expects fall-through, a discarded Sprintf or errors.New.
	"go.switch-empty-case": Fundamental,
	"go.discarded-result":  Fundamental,
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

	// Python constructs.
	"py.construct.protocol-methods":     Advanced,
	"py.construct.decorator-definition": Advanced,
	"py.construct.metaprogramming":      Advanced,
	"py.construct.generic-typing":       Advanced,
}
