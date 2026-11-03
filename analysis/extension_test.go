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
	got, err := withExtensions(context.Background(), fakeAnalyzer{}, nil)(context.Background(), []File{{Path: "a.fake"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Rule != "base" || got[1].Rule != "extra" {
		t.Errorf("findings = %+v, want the analyzer's then its extension's", got)
	}
}

// projectExtension learns the project's file count, and panics when asked to.
type projectExtension struct {
	seen  int
	panic bool
}

func (projectExtension) Language() string { return "fake" }
func (e projectExtension) Analyze(_ context.Context, files []File) ([]Finding, error) {
	return []Finding{{Rule: "project", Path: files[0].Path, Line: e.seen}}, nil
}
func (e projectExtension) ForProject(_ context.Context, files []File) Extension {
	if e.panic {
		panic("reading the project")
	}
	return projectExtension{seen: len(files)}
}

// A project extension sees every file once, then analyzes each knowing
// them; one that panics while reading falls back to analyzing files alone.
func TestProjectExtensionsReadTheProjectFirst(t *testing.T) {
	saved := extensions
	t.Cleanup(func() { extensions = saved })
	project := []File{{Path: "a.fake"}, {Path: "b.fake"}, {Path: "c.fake"}}
	for _, tt := range []struct {
		ext  projectExtension
		line int
	}{{projectExtension{}, 3}, {projectExtension{panic: true}, 0}} {
		extensions = []Extension{tt.ext}
		got, err := withExtensions(context.Background(), fakeAnalyzer{}, project)(context.Background(), project[:1])
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[1].Rule != "project" || got[1].Line != tt.line {
			t.Errorf("panic=%v: findings = %+v, want the extension to have seen %d files", tt.ext.panic, got, tt.line)
		}
	}
}
