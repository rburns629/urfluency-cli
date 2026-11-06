package analysis_test

import (
	"context"
	"testing"
	"time"

	"github.com/rburns629/urfluency-cli/analysis"
	_ "github.com/rburns629/urfluency-cli/analyzers/python"
	"github.com/rburns629/urfluency-cli/gitdata"
	"github.com/rburns629/urfluency-cli/internal/testutil"
)

// TestFindingYears dates findings by their line's commit, and refuses a
// date that the commit's own code contradicts.
func TestFindingYears(t *testing.T) {
	r := testutil.NewRepo(t)
	r.Commit("me@example.com", "2016-03-01T00:00:00Z", map[string]string{"old.py": "def load(path):\n    return open(path).read()\n"})
	// Dated 2014, but its file uses f-strings, which arrived in 2016.
	r.Commit("me@example.com", "2014-03-01T00:00:00Z", map[string]string{
		"backdated.py": "def greet(name):\n    return f\"hi {name}\"\n\n\ndef bye(name):\n    return f\"bye {name}\"\n\n\ndef again(name):\n    return f\"again {name}\"\n"})
	res, err := analysis.Scan(context.Background(), gitdata.Repo{Dir: r.Dir}, analysis.Options{Emails: []string{"me@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	var py *analysis.LanguageResult
	for i := range res.Languages {
		if res.Languages[i].Language == "python" {
			py = &res.Languages[i]
		}
	}
	if py == nil {
		t.Fatalf("no python result: %+v", res.Languages)
	}
	years := map[string]int{}
	for _, f := range py.Findings {
		if f.Rule == "py.unannotated-public-function" {
			years[f.Path] = f.Year
		}
	}
	if years["old.py"] != 2016 || years["backdated.py"] != 0 {
		t.Errorf("finding years = %v, want old.py 2016 and backdated.py 0 (untrusted)", years)
	}
	// Only the trusted file's lines have a year.
	if py.LinesByYear[2016] != 2 || len(py.LinesByYear) != 1 {
		t.Errorf("lines by year = %v, want 2 lines in 2016", py.LinesByYear)
	}
}

// TestFutureAndPreGitYears leaves out dates that cannot be real.
func TestFutureAndPreGitYears(t *testing.T) {
	r := testutil.NewRepo(t)
	r.Commit("me@example.com", "2003-01-01T00:00:00Z", map[string]string{"a.py": "def a(x):\n    return x\n"})
	r.Commit("me@example.com", time.Now().AddDate(2, 0, 0).UTC().Format(time.RFC3339), map[string]string{"b.py": "def b(x):\n    return x\n"})
	res, err := analysis.Scan(context.Background(), gitdata.Repo{Dir: r.Dir}, analysis.Options{Emails: []string{"me@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, lr := range res.Languages {
		if lr.Language != "python" {
			continue
		}
		if len(lr.LinesByYear) != 0 {
			t.Errorf("lines by year = %v, want none", lr.LinesByYear)
		}
		for _, f := range lr.Findings {
			if f.Year != 0 {
				t.Errorf("%s:%d dated %d, want 0", f.Path, f.Line, f.Year)
			}
		}
	}
}

// TestIdiomFunctions counts the functions an idiom is used in, so a single
// file can show one.
func TestIdiomFunctions(t *testing.T) {
	r := testutil.NewRepo(t)
	r.Commit("me@example.com", "2026-01-01T00:00:00Z", map[string]string{"one.py": `def a(x) -> int:
    return x


def b(x) -> int:
    return x


def c(x) -> int:
    return x
`})
	res, err := analysis.Scan(context.Background(), gitdata.Repo{Dir: r.Dir}, analysis.Options{Emails: []string{"me@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, lr := range res.Languages {
		if lr.Language == "python" {
			if u := lr.Idioms["py.idiom.type-hints"]; u.Uses != 3 || u.Files != 1 || u.Functions != 3 {
				t.Errorf("type hints = %+v, want 3 uses in 1 file and 3 functions", u)
			}
			return
		}
	}
	t.Fatal("no python result")
}
