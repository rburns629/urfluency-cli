package rules

// idiom builds a positive rule: a practice that shows fluency in a language.
func idiom(id, title, shows string, languages ...string) Rule {
	return Rule{ID: id, Category: Idiom, Languages: languages, Title: title, Why: shows}
}

// construct builds a positive rule for an advanced part of a language the
// code uses; it shows capability without counting in the idiom range.
func construct(id, title, shows string, languages ...string) Rule {
	return Rule{ID: id, Category: Construct, Languages: languages, Title: title, Why: shows}
}

func init() {
	js := []string{"javascript", "typescript"}
	Register(
		idiom("go.idiom.error-wrapping", "Errors wrapped with %w", "Adds context while keeping the cause inspectable with errors.Is and errors.As.", "go"),
		idiom("go.idiom.error-inspection", "errors.Is and errors.As", "Checks error identity and type through wrapping instead of comparing strings.", "go"),
		idiom("go.idiom.custom-error-type", "Custom error types", "Gives callers typed errors they can inspect and handle.", "go"),
		idiom("go.idiom.context-first", "context.Context as the first parameter", "Carries cancellation and deadlines through the call chain, the standard Go signature.", "go"),
		idiom("go.idiom.cancellation", "select on ctx.Done()", "Stops waiting work when the caller cancels.", "go"),
		idiom("go.idiom.defer-cleanup", "defer for cleanup", "Releases files, locks, and contexts on every return path.", "go"),
		idiom("go.idiom.structured-concurrency", "errgroup or semaphores", "Bounds goroutines and collects their errors instead of fire-and-forget.", "go"),
		idiom("go.idiom.generics", "Type parameters", "Writes reusable, type-safe code without interface{} and assertions.", "go"),
		idiom("go.idiom.small-interface", "Small interfaces", "Defines interfaces of one to three methods, which keep dependencies narrow.", "go"),
		idiom("go.idiom.table-driven-test", "Table-driven subtests", "Covers many cases in one readable test with t.Run per case.", "go"),
		construct("go.construct.channels", "Channel select and directional channels", "Coordinates goroutines with select over several channels, and states which way each channel flows.", "go"),
		construct("go.construct.sync", "Atomics and advanced sync", "Shares state with sync/atomic, sync.Once, sync.Pool, sync.RWMutex, sync.Cond, or sync.Map.", "go"),
		construct("go.construct.iterators", "Iterators", "Writes iter.Seq and iter.Seq2 functions that range loops can consume.", "go"),
		construct("go.construct.reflection", "Reflection", "Inspects and builds values at run time with the reflect package.", "go"),

		idiom("py.idiom.type-hints", "Return type annotations", "Lets type checkers and readers see what functions return.", "python"),
		idiom("py.idiom.structured-data", "Dataclasses and typed models", "Uses dataclasses, Pydantic, TypedDict, or NamedTuple instead of loose dicts.", "python"),
		idiom("py.idiom.context-manager", "with blocks", "Releases files, locks, and connections even when an exception is raised.", "python"),
		idiom("py.idiom.comprehension", "Comprehensions and generator expressions", "Builds collections declaratively instead of with append loops.", "python"),
		idiom("py.idiom.generator", "Generators", "Streams values lazily with yield instead of building whole lists.", "python"),
		idiom("py.idiom.async", "async functions", "Writes concurrent I/O with async and await.", "python"),
		idiom("py.idiom.f-string", "f-strings", "Formats strings readably, the modern standard.", "python"),
		idiom("py.idiom.custom-exception", "Custom exception classes", "Gives callers specific exceptions to catch.", "python"),
		idiom("py.idiom.protocol", "typing.Protocol", "Types interfaces structurally, without inheritance.", "python"),
		idiom("py.idiom.pathlib", "pathlib", "Handles paths as objects instead of string joins.", "python"),
		idiom("py.idiom.pytest", "pytest fixtures and parametrize", "Shares setup and covers many cases without repeating tests.", "python"),
		construct("py.construct.protocol-methods", "Protocol methods", "Defines methods such as __getitem__, __iter__, or __enter__, so objects work with Python's own syntax.", "python"),
		construct("py.construct.decorator-definition", "Decorators of your own", "Writes functions that wrap other functions, keeping their names with functools.wraps.", "python"),
		construct("py.construct.metaprogramming", "Descriptors and metaclasses", "Customizes how attributes or classes behave, with __get__ and __set__ or a metaclass.", "python"),
		construct("py.construct.generic-typing", "Generic and overloaded types", "Writes types that work across types, with TypeVar, Generic, ParamSpec, @overload, or type parameters.", "python"),

		idiom("js.idiom.optional-chaining", "Optional chaining (?.)", "Reads nested values safely without long && chains.", js...),
		idiom("js.idiom.nullish-coalescing", "Nullish coalescing (??)", "Defaults only null and undefined, unlike || which also replaces 0 and \"\".", js...),
		idiom("js.idiom.async-await", "async and await", "Writes asynchronous code that reads top to bottom, with try/catch for errors.", js...),
		idiom("js.idiom.destructuring", "Destructuring", "Unpacks objects and arrays clearly at the point of use.", js...),
		idiom("js.idiom.concurrent-promises", "Promise.all and friends", "Runs independent async work concurrently instead of one by one.", js...),

		idiom("ts.idiom.generics", "Generics", "Writes reusable code that keeps its types.", "typescript"),
		idiom("ts.idiom.union-types", "Union types", "Models values that can be one of several shapes, checked by the compiler.", "typescript"),
		idiom("ts.idiom.type-guard", "Type guards (x is T)", "Narrows types safely with checks the compiler trusts.", "typescript"),
		idiom("ts.idiom.declared-types", "Interfaces and type aliases", "Names the shapes of data instead of leaving them implicit.", "typescript"),
		idiom("ts.idiom.unknown", "unknown instead of any", "Forces values from outside to be checked before use.", "typescript"),
		construct("js.construct.generators", "Generators and iterators", "Writes generator functions and objects that for...of can iterate, with Symbol.iterator.", js...),
		construct("js.construct.metaprogramming", "Proxy and Reflect", "Intercepts and forwards operations on objects with Proxy and Reflect.", js...),
		construct("js.construct.object-model", "The object model", "Shapes objects with prototypes, property descriptors, and getters and setters.", js...),
		construct("ts.construct.type-level", "Type-level programming", "Computes types with conditional, mapped, infer, and template literal types.", "typescript"),
		idiom("ts.idiom.utility-types", "Utility types", "Derives types with Partial, Pick, Omit, and Record instead of repeating them.", "typescript"),
	)
}
