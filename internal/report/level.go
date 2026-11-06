package report

import (
	"github.com/rburns629/urfluency-cli/analysis"
	"github.com/rburns629/urfluency-cli/rules"
)

// A language's level states what its code proves its author knows; its score
// says how cleanly it is written (DESIGN.md, "Levels from evidence"):
//
//   - Beginner: fundamental mistakes at a meaningful rate.
//   - Intermediate: no fundamental pattern; the default for competent code.
//   - Advanced: an advanced idiom or construct and another of intermediate
//     tier or above, with few mistakes at advanced tier.
//   - Expert: three distinct advanced idioms or constructs, almost no
//     mistakes at advanced tier, and a score of 85 or more.
const (
	// beginnerRate is the era-weighted rate of fundamental findings, per
	// 1,000 lines, that marks a beginner: the rate at which a category scores
	// 50. beginnerRules distinct fundamental rules at beginnerRulesRate or
	// more mark one too: several kinds of basic mistake in modest code. The
	// floor keeps a large codebase, where three kinds turn up once each in
	// half a million lines (black, SQLAlchemy), from reading as a beginner's.
	beginnerRate      = 10.0
	beginnerRules     = 3
	beginnerRulesRate = 3.0
	// advancedSlips and expertSlips bound the era-weighted rate of
	// advanced-tier findings, per 1,000 lines, that each level allows.
	advancedSlips = 5.0
	expertSlips   = 1.0
	expertScore   = 85
	// expertShows is how many distinct advanced idioms or constructs Expert
	// needs; Advanced needs one, and advancedShows of intermediate tier or
	// above in all.
	expertShows   = 3
	advancedShows = 2
)

// demonstrated reports whether owned code shows an idiom or construct: at
// least minIdiomUses uses across minIdiomFiles files or functions, so one
// copied snippet does not count but a single, well-written module can.
func demonstrated(u analysis.IdiomUse) bool {
	return u.Uses >= minIdiomUses && (u.Files >= minIdiomFiles || u.Functions >= minIdiomFiles)
}

// Evidence is what a language's level rests on.
type Evidence struct {
	// Capability is the highest tier of idiom or construct the code shows
	// with enough company to read as command of it: advanced, intermediate,
	// or basic.
	Capability string `json:"capability"`
	// Shown counts the distinct idioms and constructs demonstrated at
	// intermediate tier or above, and at advanced tier.
	Intermediate int `json:"intermediate_shown"`
	Advanced     int `json:"advanced_shown"`
	// FundamentalRate and AdvancedRate are era-weighted findings per 1,000
	// lines at fundamental and advanced tier; FundamentalRules counts the
	// distinct fundamental rules found.
	FundamentalRate  float64 `json:"fundamental_per_1000_lines"`
	FundamentalRules int     `json:"fundamental_rules"`
	AdvancedRate     float64 `json:"advanced_per_1000_lines"`
}

// languageEvidence gathers a language's evidence for its level.
func languageEvidence(lr analysis.LanguageResult) Evidence {
	var e Evidence
	for _, r := range rules.ForLanguage(lr.Language) {
		if !r.Category.Positive() || !demonstrated(lr.Idioms[r.ID]) {
			continue
		}
		switch r.Level() {
		case rules.Advanced:
			e.Advanced++
			e.Intermediate++
		case rules.Intermediate:
			e.Intermediate++
		}
	}
	e.Capability = string(rules.Basic)
	switch {
	case e.Advanced >= 1 && e.Intermediate >= advancedShows:
		e.Capability = string(rules.Advanced)
	case e.Intermediate >= advancedShows:
		e.Capability = string(rules.Intermediate)
	}
	if lr.OwnedLines < 1 {
		return e
	}
	fundamental, advanced := 0.0, 0.0
	distinct := map[string]bool{}
	for _, f := range lr.Findings {
		r, ok := rules.Lookup(f.Rule)
		if !ok {
			continue
		}
		w := r.Era.Weight(f.Year)
		switch r.Level() {
		case rules.Fundamental:
			fundamental += w
			if w > 0 {
				distinct[r.ID] = true
			}
		case rules.Advanced:
			advanced += w
		}
	}
	kLines := float64(lr.OwnedLines) / 1000
	e.FundamentalRate, e.FundamentalRules, e.AdvancedRate = round2(fundamental/kLines), len(distinct), round2(advanced/kLines)
	return e
}

// languageLevel is the level the evidence and score support.
func languageLevel(e Evidence, score int) string {
	switch {
	case e.FundamentalRate >= beginnerRate || e.FundamentalRules >= beginnerRules && e.FundamentalRate >= beginnerRulesRate:
		return "Beginner"
	case e.Advanced >= expertShows && e.AdvancedRate < expertSlips && score >= expertScore:
		return "Expert"
	case e.Capability == string(rules.Advanced) && e.AdvancedRate < advancedSlips:
		return "Advanced"
	}
	return "Intermediate"
}

// evidenceFull is the logic, in functions plus their cognitive complexity,
// from which a language's rating has medium confidence; five times it, high.
// It is about what 2,000 lines of typical code hold (120 to 220 units per
// 1,000 lines across well-known Python projects). Without function evidence,
// lines count instead: medium from 2,000, high from 10,000.
const evidenceFull = 320

// languageConfidence is how much a language's rating rests on. Volume sets
// confidence, never the score.
func languageConfidence(lr analysis.LanguageResult) string {
	amount, full := lr.OwnedLines, 2000
	if e := lr.Evidence; e != nil && e.Functions > 0 {
		amount, full = e.Functions+e.Branches, evidenceFull
	}
	switch {
	case amount >= 5*full:
		return "high"
	case amount >= full:
		return "medium"
	}
	return "low"
}
