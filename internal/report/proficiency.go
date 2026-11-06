package report

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/rburns629/urfluency-cli/analysis"
	"github.com/rburns629/urfluency-cli/rules"
)

// ProficiencyModel versions the scoring below. Its constants are reasoned
// starting points, not yet calibrated against outcomes (see DESIGN.md).
const ProficiencyModel = "local-0.5-uncalibrated"

// Proficiency rates one language from the user's own code: how much of the
// language's idiom range they use, and how cleanly they write it.
type Proficiency struct {
	Score      int                      `json:"score"`      // 0–100
	Level      string                   `json:"level"`      // Beginner, Intermediate, Advanced, Expert
	Confidence string                   `json:"confidence"` // low, medium, high, from volume
	Range      int                      `json:"range"`      // 0–100: share of the language's idioms demonstrated
	Categories map[string]CategoryScore `json:"categories"`
	Model      string                   `json:"model"`
	// Evidence is what the level rests on: the capability the code shows
	// and its fundamental and advanced-tier mistakes.
	Evidence Evidence `json:"evidence"`
}

// CategoryScore rates one category of problems, such as type safety.
type CategoryScore struct {
	Score     int     `json:"score"`
	Band      string  `json:"band"` // Strong, Solid, Developing, Focus area
	PerKLines float64 `json:"per_1000_lines"`
}

// IdiomResult is an idiom the user demonstrated.
type IdiomResult struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Uses  int    `json:"uses"`
	Files int    `json:"files"`
	Why   string `json:"why"`
}

// scoredCategories are the problem categories a language score draws on, with
// the findings rate per 1,000 lines at which a category scores 50. Security
// issues weigh far more than style.
var scoredCategories = map[rules.Category]float64{
	rules.Security:            0.5,
	rules.TypeSafety:          10,
	rules.CleanCode:           10,
	rules.LanguageProficiency: 10,
}

const (
	// rangeWeight is the share of the score from idiom range; the rest is from
	// category scores.
	rangeWeight = 0.35
	// weakestLead caps the score this far above the weakest category, so a
	// strong category cannot hide a weak one.
	weakestLead = 30
	// An idiom counts as demonstrated with at least this many uses across at
	// least this many files or functions (demonstrated).
	minIdiomUses  = 3
	minIdiomFiles = 2
)

// proficiency scores a language with owned code; it returns nil otherwise.
// Any amount of code is rated: volume sets its confidence, never its score.
// counts are findings per category weighted by their rules' eras. It also
// returns each idiom's weight in the idiom range: 1 when demonstrated, and
// otherwise its era share of the owned lines, so code from before an idiom
// existed is not marked down for not using it.
func proficiency(lr analysis.LanguageResult, counts map[rules.Category]float64) (*Proficiency, []IdiomResult, map[string]float64) {
	var idioms []IdiomResult
	catalog, shown, applicable, weights := 0.0, 0, map[rules.Category]bool{}, map[string]float64{}
	for _, r := range rules.ForLanguage(lr.Language) {
		switch u := lr.Idioms[r.ID]; {
		case r.Category == rules.Idiom:
			weights[r.ID] = eraShare(r.Era, lr)
			if demonstrated(u) {
				idioms = append(idioms, IdiomResult{ID: r.ID, Title: r.Title, Uses: u.Uses, Files: u.Files, Why: r.Why})
				weights[r.ID] = 1
				shown++
			}
			catalog += weights[r.ID]
		case r.Category == rules.Construct:
			// Constructs show capability, listed with the idioms, but stay
			// out of the idiom range.
			if demonstrated(u) {
				idioms = append(idioms, IdiomResult{ID: r.ID, Title: r.Title, Uses: u.Uses, Files: u.Files, Why: r.Why})
			}
		default:
			if _, scored := scoredCategories[r.Category]; !scored {
				continue
			}
			applicable[r.Category] = true
		}
	}
	// Ties keep the catalog's ID order, so the order is the same everywhere.
	sort.SliceStable(idioms, func(i, j int) bool { return idioms[i].Uses > idioms[j].Uses })
	if lr.OwnedLines < 1 || catalog == 0 || len(applicable) == 0 {
		return nil, idioms, weights
	}

	p := &Proficiency{Categories: map[string]CategoryScore{}, Model: ProficiencyModel}
	kLines := float64(lr.OwnedLines) / 1000
	var scores []float64
	for c := range applicable {
		rate := counts[c] / kLines
		score := categoryScore(c, rate)
		p.Categories[string(c)] = CategoryScore{Score: int(math.Round(score)), Band: band(score), PerKLines: round2(rate)}
		scores = append(scores, score)
	}
	rng := min(100, 100*float64(shown)/catalog)
	p.Score, p.Range = int(math.Round(blend(rng, scores))), int(math.Round(rng))
	p.Confidence = languageConfidence(lr)
	p.Evidence = languageEvidence(lr)
	p.Level = languageLevel(p.Evidence, p.Score)
	return p, idioms, weights
}

// eraShare is the share of a language's owned lines on which a practice of
// era e would count: lines without a year in full, dated lines by e.Weight.
func eraShare(e rules.Era, lr analysis.LanguageResult) float64 {
	if e == (rules.Era{}) || lr.OwnedLines == 0 {
		return 1
	}
	undated, sum := lr.OwnedLines, 0.0
	for y, n := range lr.LinesByYear {
		undated -= n
		sum += float64(n) * e.Weight(y)
	}
	// Capped, for facts whose years claim more lines than the language has.
	return min(1, (float64(max(undated, 0))+sum)/float64(lr.OwnedLines))
}

// categoryScore rates one category from its findings per 1,000 lines: 100
// with none, 50 at the category's reference rate.
func categoryScore(c rules.Category, rate float64) float64 {
	return 100 / (1 + rate/scoredCategories[c])
}

// blend is the language score: idiom range and the category scores' average,
// capped above the weakest category.
func blend(rng float64, categories []float64) float64 {
	sum, weakest := 0.0, 100.0
	for _, s := range categories {
		sum += s
		weakest = min(weakest, s)
	}
	score := rangeWeight*rng + (1-rangeWeight)*sum/float64(len(categories))
	return min(score, weakest+weakestLead)
}

func band(score float64) string {
	switch {
	case score >= 85:
		return "Strong"
	case score >= 70:
		return "Solid"
	case score >= 50:
		return "Developing"
	}
	return "Focus area"
}

// level classifies a 0–100 rating of experience or habit, such as a
// framework or commit messages. A language's level comes from evidence
// instead (languageLevel).
func level(score int) string {
	switch {
	case score >= 85:
		return "Expert"
	case score >= 70:
		return "Advanced"
	case score >= 40:
		return "Intermediate"
	}
	return "Beginner"
}

// experience rates sustained use of a framework or tool from the repositories
// and owned files that use it: ten repositories and 200 files rate 100. It
// measures how much, not how well; language scores measure how well.
func experience(repos, files int) int { return experienceAt(repos, files, 10, 200) }

// areaScales set the repositories and files that rate a design area 100.
// Broad areas spread across many files of a project; narrow ones sit in a
// few modules per service, such as one publisher or one auth middleware, so
// they need fewer files. Unlisted areas are medium.
var areaScales = map[string][2]int{
	"cloud": {25, 500}, "api": {25, 500}, "data": {25, 500}, "frontend": {25, 500}, "mobile": {25, 500},
	"messaging": {15, 100}, "auth": {15, 100}, "observability": {15, 100}, "cli": {15, 100}, "ai": {15, 100},
}

// areaExperience rates a design area on its scale.
func areaExperience(area string, repos, files int) int {
	scale, ok := areaScales[area]
	if !ok {
		scale = [2]int{15, 200}
	}
	return experienceAt(repos, files, scale[0], scale[1])
}

// experienceAt grows with the logarithm of use, so the first projects count
// most; repositories weigh more than files, since one large project can
// reflect a team's choices.
func experienceAt(repos, files, fullRepos, fullFiles int) int {
	r := math.Min(1, math.Log2(1+float64(repos))/math.Log2(1+float64(fullRepos)))
	f := math.Min(1, math.Log2(1+float64(files))/math.Log2(1+float64(fullFiles)))
	return int(math.Round(60*r + 40*f))
}

// experienceConfidence grows with the number of repositories, since one
// project can reflect a team's choices more than the user's.
func experienceConfidence(repos int) string {
	switch {
	case repos >= 5:
		return "high"
	case repos >= 2:
		return "medium"
	}
	return "low"
}

// writeProficiency prints a language's score, its category bands, and the idioms
// it demonstrates.
func writeProficiency(b *strings.Builder, l Language) {
	if p := l.Proficiency; p != nil {
		fmt.Fprintf(b, "  Proficiency: %d/100 · %s (%s confidence) · idiom range %d%%\n", p.Score, p.Level, p.Confidence, p.Range)
		names := make([]string, 0, len(p.Categories))
		for c := range p.Categories {
			names = append(names, c)
		}
		sort.Strings(names)
		line := "   "
		for _, c := range names {
			cs := p.Categories[c]
			line += fmt.Sprintf(" %s %d (%s);", c, cs.Score, cs.Band)
		}
		fmt.Fprintf(b, "%s\n", line[:len(line)-1])
	}
	if len(l.Idioms) > 0 {
		fmt.Fprintf(b, "  Shows\n")
		for _, i := range l.Idioms {
			fmt.Fprintf(b, "    + %s: %d uses in %d files\n", i.Title, i.Uses, i.Files)
		}
	}
}
