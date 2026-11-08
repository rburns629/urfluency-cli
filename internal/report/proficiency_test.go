package report

import (
	"testing"

	"github.com/roburns/urfluency-cli/analysis"
	"github.com/roburns/urfluency-cli/rules"

	_ "github.com/roburns/urfluency-cli/analyzers/golang"
)

func goIdioms() map[string]analysis.IdiomUse {
	all := map[string]analysis.IdiomUse{}
	for _, r := range rules.ForLanguage("go") {
		if r.Category == rules.Idiom {
			all[r.ID] = analysis.IdiomUse{Uses: 5, Files: 3}
		}
	}
	return all
}

func TestProficiency(t *testing.T) {
	tests := []struct {
		name       string
		lines      int
		idioms     map[string]analysis.IdiomUse
		counts     map[rules.Category]float64
		score      int
		confidence string
	}{
		{"clean code, no idioms", 10000, nil, nil, 66, "high"},
		{"clean code, every idiom", 10000, goIdioms(), nil, 98, "high"},
		// Type safety at 70 per 1,000 lines scores 12.5, which caps the language
		// at 42.5 however strong the rest is; the volume weighting then moves it
		// toward 50.
		{"one weak category", 10000, goIdioms(), map[rules.Category]float64{rules.TypeSafety: 700}, 45, "high"},
		{"one-off idioms do not count", 3000, map[string]analysis.IdiomUse{"go.idiom.generics": {Uses: 2, Files: 1}}, nil, 62, "medium"},
		// Volume weighs the score: a small file is little evidence.
		{"a small, clean, idiomatic file", 300, goIdioms(), nil, 62, "low"},
		{"a few lines", 12, nil, nil, 50, "low"},
	}
	for _, tc := range tests {
		lr := analysis.LanguageResult{Language: "go", OwnedLines: tc.lines, Idioms: tc.idioms}
		p, _, _ := proficiency(lr, tc.counts)
		if p == nil || p.Score != tc.score || p.Confidence != tc.confidence {
			t.Errorf("%s: proficiency = %+v, want %d %s", tc.name, p, tc.score, tc.confidence)
		}
	}
	if p, _, _ := proficiency(analysis.LanguageResult{Language: "go"}, nil); p != nil {
		t.Errorf("scored a language with no code: %+v", p)
	}
}

// pyShown demonstrates the given Python idioms and constructs in one file,
// each in three functions.
func pyShown(ids ...string) map[string]analysis.IdiomUse {
	m := map[string]analysis.IdiomUse{}
	for _, id := range ids {
		m[id] = analysis.IdiomUse{Uses: 3, Files: 1, Functions: 3}
	}
	return m
}

func pyFindings(rule string, n, year int) []analysis.Finding {
	var out []analysis.Finding
	for range n {
		out = append(out, analysis.Finding{Rule: rule, Year: year})
	}
	return out
}

// TestLevels: a level states what the code proves, apart from its score.
func TestLevels(t *testing.T) {
	advanced := pyShown("py.construct.protocol-methods", "py.idiom.type-hints", "py.idiom.f-string")
	expert := pyShown("py.construct.protocol-methods", "py.construct.decorator-definition", "py.construct.generic-typing", "py.idiom.async", "py.idiom.type-hints",
		"py.idiom.comprehension", "py.idiom.generator", "py.idiom.structured-data", "py.idiom.custom-exception", "py.idiom.f-string", "py.idiom.context-manager")
	for _, tc := range []struct {
		name     string
		lines    int
		idioms   map[string]analysis.IdiomUse
		findings []analysis.Finding
		level    string
	}{
		{"competent code with no evidence of more", 2000, nil, nil, "Intermediate"},
		{"basic mistakes at a high rate", 1000, nil, pyFindings("py.is-literal-comparison", 10, 0), "Beginner"},
		{"one basic slip in a short file", 100, nil, pyFindings("py.is-literal-comparison", 1, 0), "Beginner"},
		{"basic slips in plenty of code", 5000, nil, pyFindings("py.is-literal-comparison", 5, 0), "Intermediate"},
		// Several kinds of fundamental mistake are tested in urfluency-app,
		// where the engine's fundamental rules are in the catalog.
		// Practice findings lower the score but never make a beginner.
		{"many practice findings", 250, nil, pyFindings("py.open-without-with", 20, 0), "Intermediate"},
		{"advanced constructs used correctly", 300, advanced, nil, "Advanced"},
		{"command of the advanced parts", 20000, expert, nil, "Expert"},
		// Expert's score of 85 needs enough code: the same evidence in 2,000
		// lines reads Advanced.
		{"command of the advanced parts, in a small sample", 2000, expert, nil, "Advanced"},
		// Expert also needs a score of 85: three advanced constructs with a
		// narrow idiom range read Advanced.
		{"advanced parts, narrow range", 2000, pyShown("py.construct.protocol-methods", "py.construct.decorator-definition", "py.construct.generic-typing", "py.idiom.type-hints"), nil, "Advanced"},
		// A literal compared with is was never right, so it counts whenever written.
		{"basic mistakes count whenever written", 1000, nil, pyFindings("py.is-literal-comparison", 10, 2001), "Beginner"},
		// A bare except is practice: it lowers the score, never the level.
		{"many bare excepts", 1000, nil, pyFindings("py.bare-except", 20, 0), "Intermediate"},
	} {
		lr := analysis.LanguageResult{Language: "python", OwnedLines: tc.lines, Idioms: tc.idioms, Findings: tc.findings}
		lang := buildLanguage(lr, false)
		if got := lang.Proficiency.Level; got != tc.level {
			t.Errorf("%s: level %s (score %d, evidence %+v), want %s", tc.name, got, lang.Proficiency.Score, lang.Proficiency.Evidence, tc.level)
		}
	}
}

// TestIdiomEras leaves idioms out of the range for code written before they
// existed, and keeps them in for code without a year.
func TestIdiomEras(t *testing.T) {
	idioms := goIdioms()
	for _, id := range []string{"go.idiom.generics", "go.idiom.error-wrapping", "go.idiom.error-inspection"} {
		delete(idioms, id)
	}
	undated := analysis.LanguageResult{Language: "go", OwnedLines: 10000, Idioms: idioms}
	from2018 := analysis.LanguageResult{Language: "go", OwnedLines: 10000, Idioms: idioms, LinesByYear: map[int]int{2018: 10000}}
	pu, _, _ := proficiency(undated, nil)
	p18, _, w := proficiency(from2018, nil)
	if pu.Range >= 100 || p18.Range != 100 || p18.Score != 98 {
		t.Errorf("range undated %d, from 2018 %d (score %d); want under 100, then 100", pu.Range, p18.Range, p18.Score)
	}
	if w["go.idiom.generics"] != 0 || w["go.idiom.defer-cleanup"] != 1 {
		t.Errorf("idiom weights = %v", w)
	}
	// Half the lines from 2020, half undated: generics, from 2022, weighs half.
	half := analysis.LanguageResult{Language: "go", OwnedLines: 10000, LinesByYear: map[int]int{2020: 5000}}
	if _, _, w := proficiency(half, nil); w["go.idiom.generics"] != 0.5 {
		t.Errorf("generics weight = %v, want 0.5", w["go.idiom.generics"])
	}
}

// TestLegacyFindings counts findings from before a rule's practice was
// established at their era weight, and lists them all.
func TestLegacyFindings(t *testing.T) {
	lr := analysis.LanguageResult{Language: "python", OwnedLines: 10000, Findings: []analysis.Finding{
		{Rule: "py.unannotated-public-function", Year: 2014}, // before annotations: 0
		{Rule: "py.unannotated-public-function", Year: 2017}, // optional: 0.5
		{Rule: "py.unannotated-public-function", Year: 2024}, // 1
		{Rule: "py.unannotated-public-function"},             // no year: 1
		{Rule: "py.bare-except", Year: 2012},                 // no era: 1
	}}
	lang := buildLanguage(lr, false)
	got := map[string]RuleResult{}
	for _, w := range lang.Weaknesses {
		got[w.ID] = w
	}
	if w := got["py.unannotated-public-function"]; w.Count != 4 || w.Legacy != 2 || w.weighted != 2.5 {
		t.Errorf("annotations: count %d, legacy %d, weighted %v; want 4, 2, 2.5", w.Count, w.Legacy, w.weighted)
	}
	if w := got["py.bare-except"]; w.Count != 1 || w.Legacy != 0 {
		t.Errorf("bare except: count %d, legacy %d; want 1, 0", w.Count, w.Legacy)
	}
	if lang.Categories["type-safety"] != 4 || lang.weighted["type-safety"] != 2.5 {
		t.Errorf("type safety: %d shown, %v scored; want 4 and 2.5", lang.Categories["type-safety"], lang.weighted["type-safety"])
	}
}

// TestByVolume: little code moves a score toward neutral, either way, and
// sustained use adds a little.
func TestByVolume(t *testing.T) {
	for _, tc := range []struct {
		score       float64
		lines, want int
	}{
		{64, 1700, 60},  // a small PowerShell codebase
		{64, 66000, 67}, // a large Python one, with the same quality
		{30, 500, 44},   // a weak score from little code is weak evidence too
		{100, 100_000, 100},
	} {
		if got := int(byVolume(tc.score, tc.lines) + 0.5); got != tc.want {
			t.Errorf("byVolume(%v, %d) = %d, want %d", tc.score, tc.lines, got, tc.want)
		}
	}
}
