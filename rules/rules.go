// Package rules is the versioned catalog that every finding references.
package rules

import "sort"

// Version identifies the catalog; it changes whenever rules are added or redefined.
const Version = "0.15"

// Category groups rules into the metrics users see.
type Category string

const (
	CleanCode           Category = "clean-code"
	Architecture        Category = "architecture"
	TypeSafety          Category = "type-safety"
	LanguageProficiency Category = "language-proficiency"
	Security            Category = "security"
	AIEngineering       Category = "ai-engineering"
	// Idiom rules are positive: they record practices the code uses well and
	// count toward proficiency, never against it.
	Idiom Category = "idiom"
	// Construct rules are positive too: advanced parts of a language the code
	// uses, such as defining protocol methods. They show capability for the
	// level and stay out of the idiom range.
	Construct Category = "construct"
)

// Positive reports whether a category records what code does well.
func (c Category) Positive() bool { return c == Idiom || c == Construct }

// Rule describes one detectable practice and how to improve on it.
type Rule struct {
	ID        string
	Category  Category
	Languages []string
	Framework string
	Title     string
	Why       string
	Focus     string
	// Era is when the practice became possible and expected; zero for most
	// rules, which flag what was never good practice.
	Era Era
	// Tier places the rule on the path from learning a language to
	// commanding it (see Tier); empty is Practice for a problem and Basic
	// for an idiom or construct.
	Tier Tier
}

var (
	catalog    = map[string]Rule{}
	duplicates []string
)

// Register adds rules to the catalog. A duplicate ID keeps the first definition
// and is recorded for Duplicates, which tests check.
func Register(rs ...Rule) {
	for _, r := range rs {
		if _, exists := catalog[r.ID]; exists {
			duplicates = append(duplicates, r.ID)
			continue
		}
		if e, ok := eras[r.ID]; ok && r.Era == (Era{}) {
			r.Era = e
		}
		if t, ok := tiers[r.ID]; ok && r.Tier == "" {
			r.Tier = t
		}
		catalog[r.ID] = r
	}
}

// Duplicates returns IDs that were registered more than once.
func Duplicates() []string { return append([]string(nil), duplicates...) }

// standardsBase is where clean-agent-code's standards are published.
const standardsBase = "https://github.com/rotburn/clean-agent-code/blob/main/"

// ruleStandards link rules to the clean-agent-code section that covers them,
// where a category default would be too broad.
var ruleStandards = map[string]string{
	"clean.cognitive-complexity": "standards/ARCHITECTURE.md#simplest-sufficient-solution",
	"prompt.unverified-change":   "standards/QUALITY_GATES.md",
}

// categoryStandards are the documents that cover a whole category. Clean-code and
// language-proficiency rules are language-specific and have no default.
var categoryStandards = map[Category]string{
	TypeSafety:   "standards/TYPE_SAFETY.md",
	Security:     "standards/SECURITY.md",
	Architecture: "standards/ARCHITECTURE.md",
}

// Standard returns the clean-agent-code document that explains the practice
// behind a rule, or "" when none covers it.
func (r Rule) Standard() string {
	if p, ok := ruleStandards[r.ID]; ok {
		return standardsBase + p
	}
	if p, ok := categoryStandards[r.Category]; ok {
		return standardsBase + p
	}
	return ""
}

// Lookup returns the rule with the given ID.
func Lookup(id string) (Rule, bool) {
	r, ok := catalog[id]
	return r, ok
}

// All returns every rule in the catalog, sorted by ID.
func All() []Rule {
	out := make([]Rule, 0, len(catalog))
	for _, r := range catalog {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ForLanguage returns the rules that apply to a language, sorted by ID.
func ForLanguage(language string) []Rule {
	var out []Rule
	for _, r := range catalog {
		for _, l := range r.Languages {
			if l == language {
				out = append(out, r)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
