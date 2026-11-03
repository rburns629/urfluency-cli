package analysis

import (
	"context"
	"testing"
)

type fakeAnalyzer struct{}

func (fakeAnalyzer) Language() string     { return "fake" }
func (fakeAnalyzer) Extensions() []string { return []string{".fake"} }
func (fakeAnalyzer) Skip(File) bool       { return false }
func (fakeAnalyzer) Analyze(_ context.Context, files []File) ([]Finding, error) {
	return []Finding{{Rule: "base", Path: files[0].Path, Line: 1}}, nil
}

type fakeExtension struct{ lang string }

func (e fakeExtension) Language() string { return e.lang }
func (fakeExtension) Analyze(_ context.Context, files []File) ([]Finding, error) {
	return []Finding{{Rule: "extra", Path: files[0].Path, Line: 2}}, nil
}

// An extension's findings follow its own language's analyzer's, and only
// that language's.
func TestExtensionsJoinTheirLanguage(t *testing.T) {
	saved := extensions
	t.Cleanup(func() { extensions = saved })
	extensions = []Extension{fakeExtension{"fake"}, fakeExtension{"other"}}
	got, err := withExtensions(fakeAnalyzer{})(context.Background(), []File{{Path: "a.fake"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Rule != "base" || got[1].Rule != "extra" {
		t.Errorf("findings = %+v, want the analyzer's then its extension's", got)
	}
}
