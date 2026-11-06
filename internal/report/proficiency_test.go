package report

import (
	"testing"

	"github.com/rburns629/urfluency-cli/analysis"
	"github.com/rburns629/urfluency-cli/rules"

	_ "github.com/rburns629/urfluency-cli/analyzers/golang"
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
		level      string
		confidence string
	}{
		{"clean code, no idioms", 10000, nil, nil, 65, "Intermediate", "high"},
		{"clean code, every idiom", 10000, goIdioms(), nil, 100, "Expert", "high"},
		// Type safety at 70 per 1,000 lines scores 12.5, which caps the language
		// at 42.5 however strong the rest is.
		{"one weak category", 10000, goIdioms(), map[rules.Category]float64{rules.TypeSafety: 700}, 43, "Intermediate", "high"},
		{"one-off idioms do not count", 3000, map[string]analysis.IdiomUse{"go.idiom.generics": {Uses: 2, Files: 1}}, nil, 65, "Intermediate", "medium"},
		// Under 2,000 lines, even perfect code is capped at Beginner.
		{"too little code for more than Beginner", 1999, goIdioms(), nil, 39, "Beginner", "low"},
		{"enough code", 2000, goIdioms(), nil, 100, "Expert", "medium"},
	}
	for _, tc := range tests {
		lr := analysis.LanguageResult{Language: "go", OwnedLines: tc.lines, Idioms: tc.idioms}
		p, _, _ := proficiency(lr, tc.counts)
		if p == nil || p.Score != tc.score || p.Level != tc.level || p.Confidence != tc.confidence {
			t.Errorf("%s: proficiency = %+v, want %d %s %s", tc.name, p, tc.score, tc.level, tc.confidence)
		}
	}
	if p, _, _ := proficiency(analysis.LanguageResult{Language: "go", OwnedLines: MinOwnedLines - 1}, nil); p != nil {
		t.Errorf("scored a language with too little code: %+v", p)
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
	if pu.Range >= 100 || p18.Range != 100 || p18.Score != 100 {
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
