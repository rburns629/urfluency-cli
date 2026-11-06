package parsing

import (
	"bytes"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	ts "github.com/tree-sitter/go-tree-sitter"
)

func TestTreeParentMatchesNodeParent(t *testing.T) {
	tree, err := Parse(Python, []byte("def f(x):\n    if x:\n        return open(open(x))\n    return [1, 2, (3, 4)]\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer tree.Close()
	checked := 0
	var visit func(n *ts.Node)
	visit = func(n *ts.Node) {
		want, got := n.Parent(), tree.Parent(n)
		if (want == nil) != (got == nil) || (want != nil && want.Id() != got.Id()) {
			t.Errorf("%s at %d: Parent = %v, want %v", n.Kind(), n.StartByte(), got, want)
		}
		checked++
		for i := uint(0); i < n.ChildCount(); i++ {
			visit(n.Child(i))
		}
	}
	visit(tree.Root())
	if checked < 20 {
		t.Errorf("checked only %d nodes", checked)
	}
}

// Reading in chunks must give the same tree as reading the whole file, across
// chunk boundaries that fall inside multi-byte characters.
func TestChunkedReadsParseLikeWholeFiles(t *testing.T) {
	src := []byte("x = '" + strings.Repeat("é€😀", 3000) + "'\ny = [" + strings.Repeat("1, ", 3000) + "]\n")
	for i := 0; i < len(src); {
		c := chunk(src, i)
		if len(c) == 0 || !utf8.Valid(c) {
			t.Fatalf("chunk at %d is empty or splits a character", i)
		}
		i += len(c)
	}
	tree, err := Parse(Python, src)
	if err != nil {
		t.Fatal(err)
	}
	defer tree.Close()
	if tree.Root().HasError() || tree.Root().EndByte() != uint(len(src)) {
		t.Errorf("chunked parse: error %v, end %d of %d", tree.Root().HasError(), tree.Root().EndByte(), len(src))
	}
}

// Invalid UTF-8 is replaced byte for byte before parsing, so offsets still
// index the original source, and a long run of it parses quickly: fuzzing
// found 4,400 bytes of 0xb5 kept the Dart grammar busy for 6.8 s.
func TestInvalidUTF8ParsesQuickly(t *testing.T) {
	valid := []byte("var s = 'µ';\n")
	if got := validUTF8(valid); &got[0] != &valid[0] {
		t.Error("valid source was copied")
	}
	mixed := []byte("a\xb5b\xe2\x82c€")
	if got := string(validUTF8(mixed)); got != "a b  c€" || len(got) != len(mixed) {
		t.Errorf("validUTF8 = %q, want %q", got, "a b  c€")
	}
	src := append([]byte("void main() {}\n"), bytes.Repeat([]byte{0xb5}, 20000)...)
	for _, g := range []Grammar{Dart, Python, Swift, Kotlin, PHP} {
		start := time.Now()
		tree, err := Parse(g, src)
		if err != nil {
			t.Fatal(err)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("parse took %v", d)
		}
		if !bytes.Equal(tree.Source, src) {
			t.Error("the tree's source is not the original")
		}
		tree.Close()
	}
}
