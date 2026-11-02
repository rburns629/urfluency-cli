package gates

import (
	"reflect"
	"testing"
)

func TestRun(t *testing.T) {
	tests := map[string][]string{
		"go test ./... && go vet ./...":                   {Lint, Tests},
		"cargo fmt --check && cargo clippy && cargo test": {Format, Lint, Tests},
		"dotnet build && dotnet test":                     {Build, Tests},
		"./gradlew build && ./gradlew test":               {Build, Tests},
		"mvn verify":                                      {Build, Tests},
		"flutter analyze && flutter test":                 {Lint, Tests},
		"swiftlint && swift test":                         {Lint, Tests},
		"clang-tidy src/*.cc && ctest":                    {Lint, Tests},
		"cargo audit":                                     {Security},
		"npx prettier --check . && npx tsc":               {Format, Types},
		"pnpm run build":                                  {Build},
		"pip-audit -r requirements.txt":                   {Security},
		"make check":                                      {Other},
		"cat main.go":                                     nil,
		"ruff check . && ruff format --check":             {Format, Lint},
		// Installing tools, or naming their files, runs nothing.
		"pip install black mypy pytest":      nil,
		"npm i -D prettier jest":             nil,
		"cat jest.config.js && cat mypy.ini": nil,
		"brew install swiftlint\nswiftlint":  {Lint},
		"pip install pytest\npytest -q":      {Tests},
		// An install and a run on one line: only the install is left out.
		"npm ci && npm test":                        {Tests},
		"pip install -r requirements.txt && pytest": {Tests},
		"go install honnef.co/go/tools/cmd/staticcheck@latest; staticcheck ./...": {Lint},
		"make test-unit":                {Tests},
		"./node_modules/.bin/jest --ci": {Tests},
	}
	for in, want := range tests {
		if got := Run(in); !reflect.DeepEqual(got, want) {
			t.Errorf("Run(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestImplied(t *testing.T) {
	got := Implied("go", map[string]bool{Tests: true}, false)
	if !got[Types] || !got[Build] || !got[Tests] {
		t.Errorf("go tests should imply types and build: %v", got)
	}
	if got := Implied("typescript", map[string]bool{Tests: true}, false); got[Types] {
		t.Error("TypeScript tests do not imply type checking")
	}
	if got := Implied("swift", map[string]bool{Lint: true}, false); got[Types] || got[Build] {
		t.Error("swiftlint does not compile Swift")
	}
	if got := Implied("go", map[string]bool{Lint: true}, true); !got[Types] || !got[Build] {
		t.Error("go vet type-checks Go")
	}
}

func TestTypeChecked(t *testing.T) {
	if got := TypeChecked("go vet ./... && swiftlint && cargo clippy"); !reflect.DeepEqual(got, []string{"go", "rust"}) {
		t.Errorf("TypeChecked = %v, want go and rust", got)
	}
}

func TestSet(t *testing.T) {
	s := Set(0).With(Tests, Lint)
	if !s.Has(Tests) || !s.Has(Lint) || s.Has(Types) || s.Has("unknown") {
		t.Errorf("set = %b", s)
	}
	if s.With(Tests) != s {
		t.Error("adding a present gate changed the set")
	}
}

// The gate lists are copies: a caller cannot change them for others.
func TestGateListsAreCopies(t *testing.T) {
	m := Mandatory()
	m[0] = "changed"
	if Mandatory()[0] != Format {
		t.Error("changing a returned list changed Mandatory")
	}
	n := Named()
	n[0] = "changed"
	if Named()[0] != Format {
		t.Error("changing a returned list changed Named")
	}
}
