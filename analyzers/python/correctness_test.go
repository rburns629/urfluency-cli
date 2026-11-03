package python

import (
	"reflect"
	"testing"
)

// Each rule fires on the mistake it names and stays quiet on the code that
// only looks like it.
func TestCorrectnessRules(t *testing.T) {
	tests := []struct {
		name string
		path string
		src  string
		want []string
	}{
		{"a dataclass with no fields", "lib/km.py", `from dataclasses import dataclass

@dataclass
class KeyMapper(dict):
    delimiter = "."

    def __init__(self, *args):
        super().__init__(*args)
`, []string{"py.dataclass-without-fields:4"}},
		{"dataclasses with fields, eq=False, or a base that may have fields", "lib/km.py", `from dataclasses import dataclass, field

@dataclass
class Point:
    x: int
    y: int = 0

@dataclass(eq=False)
class Marker:
    pass

@dataclass
class Child(Point):
    pass
`, []string{}},
		{"a __getattr__ that returns None", "lib/km.py", `class KeyMapper(dict):
    def __getattr__(self, attr):
        return self.get(attr)
`, []string{"py.getattr-without-attributeerror:2"}},
		{"a __getattr__ that raises or delegates", "lib/proxy.py", `class Proxy:
    def __getattr__(self, name):
        return getattr(self._target, name)

class Lazy:
    def __getattr__(self, name):
        try:
            return self._data[name]
        except KeyError:
            raise AttributeError(name) from None

def __getattr__(name):
    return None
`, []string{}},
		{"handlers that only re-raise", "lib/km.py", `def f() -> None:
    try:
        g()
    except Exception as e:
        raise e

def h() -> None:
    try:
        g()
    except ValueError:
        raise
`, []string{"py.reraise-only-handler:10", "py.reraise-only-handler:4"}},
		{"re-raising that does something", "lib/a.py", `def f() -> None:
    try:
        g()
    except KeyboardInterrupt:
        raise
    except Exception:
        log()

def h() -> None:
    try:
        g()
    except OSError as e:
        raise RuntimeError("failed") from e

def k() -> None:
    try:
        g()
    except OSError as e:
        raise e from None
`, []string{}},
		{"a class list changed through self", "lib/a.py", `class Cart:
    items = []

    def add(self, item: str) -> None:
        self.items.append(item)

class Index:
    seen = {}

    def mark(self, key: str) -> None:
        self.seen[key] = True
`, []string{"py.mutable-class-attribute:2", "py.mutable-class-attribute:8"}},
		{"shared registries and containers rebound or only read", "lib/a.py", `class Plugin:
    registry = {}
    tags = []
    DEFAULTS = {}

    def __init_subclass__(cls) -> None:
        cls.registry[cls.__name__] = cls

    def reset(self) -> None:
        self.tags = []

    def has(self, tag: str) -> bool:
        return tag in self.tags

class Meta:
    ordering = []

    def add(self) -> None:
        self.ordering.append("x")
`, []string{}},
		{"a test script with no tests", "tests/test_km.py", `if __name__ == "__main__":
    from keymapper import KeyMapper
    print(KeyMapper({"a": 1}))
`, []string{"py.test-file-without-tests:1"}},
		{"real tests, unittest classes, and helper modules", "tests/test_a.py", `import unittest

class Checks(unittest.TestCase):
    def runTest(self) -> None:
        self.assertTrue(True)

if __name__ == "__main__":
    unittest.main()
`, []string{}},
		{"pytest functions with a main block", "tests/test_b.py", `def test_add() -> None:
    assert 1 + 1 == 2

if __name__ == "__main__":
    test_add()
`, []string{}},
		{"markers, stubs, delegation, else clauses, and private caches", "lib/b.py", `from dataclasses import dataclass
from typing import Any, Protocol

@dataclass(slots=True)
class SkipValidation:
    """A marker with no state."""

class Cursor(Protocol):
    def __getattr__(self, key: str) -> Any: ...

class Events:
    def __getattr__(self, name: str) -> Any:
        raise NotImplementedError()

class Row:
    def __getattr__(self, name: str) -> Any:
        return self._get_by_key_impl(name, True)

class Wrapper:
    _pools = {}

    def pool(self, key: str) -> None:
        self._pools.setdefault(key, object())

def f() -> None:
    try:
        g()
    except:
        raise
    else:
        h()
`, []string{}},
		{"a launched script that asserts", "src/pkg/test_utils/scripts/test_merge.py", `def main() -> None:
    assert run() == 0

if __name__ == "__main__":
    main()
`, []string{}},
		{"a script in a tests folder that only asserts", "tests/test_smoke.py", `if __name__ == "__main__":
    assert 1 + 1 == 2
`, []string{}},
		{"a helper named like a test", "tests/test_utils.py", `def make_user() -> dict:
    return {"name": "a"}
`, []string{}},
	}
	only := map[string]bool{"py.dataclass-without-fields": true, "py.getattr-without-attributeerror": true, "py.reraise-only-handler": true,
		"py.mutable-class-attribute": true, "py.test-file-without-tests": true}
	for _, tc := range tests {
		got := []string{}
		for _, f := range findings(t, tc.path, tc.src) {
			rule := f[:len(f)-len(f[indexColon(f):])]
			if only[rule] {
				got = append(got, f)
			}
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func indexColon(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return i
		}
	}
	return len(s)
}
