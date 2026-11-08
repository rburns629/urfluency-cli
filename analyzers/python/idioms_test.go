package python

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/roburns/urfluency-cli/analysis"
	"github.com/roburns/urfluency-cli/rules"
)

func TestIdioms(t *testing.T) {
	src := `from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import pytest
from pydantic import BaseModel


@dataclass
class Point:
    x: int


class User(BaseModel):
    name: str


class NotFound(Exception):
    pass


class Reader(Protocol):
    def read(self) -> str: ...


def names(users: list[User]) -> list[str]:
    return [u.name for u in users]


def lines(path: Path):
    with open(path) as f:
        for line in f:
            yield f"{line.strip()}"


async def fetch(client):
    return await client.get("/")


@pytest.mark.parametrize("n", [1, 2])
def test_n(n):
    assert n
`
	findings, err := Analyzer{}.Analyze(context.Background(), []analysis.File{{Path: "app.py", Content: []byte(src)}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, f := range findings {
		if f.Positive && !strings.HasPrefix(f.Rule, "evidence.") {
			got[f.Rule]++
		}
	}
	want := map[string]int{
		"py.idiom.structured-data": 2, "py.idiom.custom-exception": 1, "py.idiom.protocol": 1, "py.idiom.type-hints": 2,
		"py.idiom.comprehension": 1, "py.idiom.context-manager": 1, "py.idiom.generator": 1, "py.idiom.f-string": 1,
		"py.idiom.async": 1, "py.idiom.pathlib": 1, "py.idiom.pytest": 1,
	}
	for rule, n := range want {
		if got[rule] != n {
			t.Errorf("%s = %d, want %d", rule, got[rule], n)
		}
	}
	for rule := range got {
		if r, ok := rules.Lookup(rule); !ok || r.Category != rules.Idiom && r.Category != rules.Construct {
			t.Errorf("%s is not an idiom or construct in the catalog", rule)
		}
	}
}

func TestConstructs(t *testing.T) {
	src := `import functools
from abc import ABCMeta


class Bag(dict):
    def __init__(self, items):
        super().__init__(items)

    def __repr__(self):
        return "Bag()"

    def __getitem__(self, key):
        return super().__getitem__(key)

    @property
    def __len__(self):
        return 0

    def __enter__(self):
        return self


def __getitem__(key):
    return key


def timed(fn):
    @functools.wraps(fn)
    def wrapper(*args):
        return fn(*args)
    return wrapper


def retry(times):
    def wrap(fn):
        return fn
    return wrap


def helper(items):
    def key(item):
        return item[0]
    return sorted(items, key=key)


class Meta(type):
    pass


class Plain(metaclass=ABCMeta):
    pass


class Field:
    def __set_name__(self, owner, name):
        self.name = name

    def __get__(self, obj, kind=None):
        return obj.__dict__[self.name]


T = TypeVar("T")
P = typing.ParamSpec("P")


class Box(Generic[T]):
    pass


@overload
def first(x: int) -> int: ...


def last[U](items: list[U]) -> U:
    return items[-1]


Alias = Annotated[int, "meta"]
names: Optional[List[str]] = None
`
	findings, err := Analyzer{}.Analyze(context.Background(), []analysis.File{{Path: "app.py", Content: []byte(src)}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]int{}
	for _, f := range findings {
		if strings.HasPrefix(f.Rule, "py.construct.") {
			got[f.Rule] = append(got[f.Rule], f.Line)
		}
	}
	// Protocol methods only in a class, not __init__ or __repr__, decorated
	// or not; decorators that return their inner function or use wraps, not
	// a helper that defines one; a metaclass and descriptor methods, not a
	// class that only uses a metaclass.
	want := map[string][]int{
		"py.construct.protocol-methods":     {12, 16, 19},
		"py.construct.decorator-definition": {27, 34},
		"py.construct.metaprogramming":      {46, 55, 58},
		// Type variables, Generic, @overload, and type parameters; not
		// Annotated or everyday Optional and List.
		"py.construct.generic-typing": {62, 63, 66, 70, 74},
	}
	for rule, lines := range want {
		if fmt.Sprint(got[rule]) != fmt.Sprint(lines) {
			t.Errorf("%s on lines %v, want %v", rule, got[rule], lines)
		}
		if r, ok := rules.Lookup(rule); !ok || r.Category != rules.Construct || r.Level() != rules.Advanced {
			t.Errorf("%s is not an advanced construct in the catalog", rule)
		}
	}
}
