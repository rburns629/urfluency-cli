// Package facts defines the counts an upload carries for urfluency.com's
// official model to score: the scan results the CLI's own report is built
// from, without anything that identifies code or repositories.
//
// A scan's commit hash, each finding's path and line, and each repository's
// label are dropped; findings become counts per rule. What is left are counts,
// months, and names from the catalog: languages, rules, frameworks, tools,
// libraries, and platforms. Result turns facts back into a scan result, so the
// same report code can score them; reports take Sessions as they are.
package facts

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rburns629/urfluency-cli/analysis"
	"github.com/rburns629/urfluency-cli/internal/sessions"
)

// Format versions the facts.
const Format = "1"

// Facts are one upload's counts.
type Facts struct {
	Format string `json:"format"`
	// Git is the scan of the Git repositories, Folders that of the project
	// folders without Git; either can be absent.
	Git     *Scan `json:"git,omitempty"`
	Folders *Scan `json:"folders,omitempty"`
	// Sessions are the prompting grades, present when sessions were read.
	Sessions *Sessions `json:"sessions,omitempty"`
}

// Scan is one analysis.Result without identifying fields.
type Scan struct {
	Repos             int                 `json:"repos"`
	Languages         []Language          `json:"languages"`
	OwnedLines        int                 `json:"owned_lines"`
	AILines           int                 `json:"ai_lines"`
	AIFindings        int                 `json:"ai_findings"`
	Findings          int                 `json:"findings"`
	MarkedLines       int                 `json:"marked_lines"`
	MarkedByTool      map[string]int      `json:"marked_by_tool,omitempty"`
	Durability        Durability          `json:"durability"`
	Written           Written             `json:"written"`
	Tests             Tests               `json:"tests"`
	Projects          []Project           `json:"projects,omitempty"`
	SkippedSlow       int                 `json:"skipped_slow"`
	SkippedUnanalyzed int                 `json:"skipped_unanalyzed"`
	Dismissed         int                 `json:"dismissed"`
	Declared          bool                `json:"declared"`
	Tools             map[string]Tool     `json:"tools,omitempty"`
	Commits           Commits             `json:"commits"`
	Design            map[string]Design   `json:"design,omitempty"`
	Platforms         map[string]Platform `json:"platforms,omitempty"`
	FrameworkRepos    map[string]int      `json:"framework_repos,omitempty"`
}

// Language is one analysis.LanguageResult, with findings counted per rule.
type Language struct {
	Name             string           `json:"name"`
	Frameworks       []string         `json:"frameworks,omitempty"`
	FrameworkUse     map[string]Usage `json:"framework_use,omitempty"`
	Files            int              `json:"files"`
	OwnedLines       int              `json:"owned_lines"`
	FindingsByRule   map[string]int   `json:"findings_by_rule,omitempty"`
	AssistedLines    int              `json:"assisted_lines"`
	AssistedFindings int              `json:"assisted_findings"`
	AssistedByRule   map[string]int   `json:"assisted_by_rule,omitempty"`
	TestLines        int              `json:"test_lines"`
	Idioms           map[string]Idiom `json:"idioms,omitempty"`
}

// Idiom is how often, and in how many files, owned code used an idiom.
type Idiom struct {
	Uses  int `json:"uses"`
	Files int `json:"files"`
}

// Usage is a count of repositories and of files.
type Usage struct {
	Repos int `json:"repos"`
	Files int `json:"files"`
}

// Durability is analysis.Durability.
type Durability struct {
	AssistedAdded int `json:"assisted_added"`
	AssistedFixed int `json:"assisted_fixed"`
	OtherAdded    int `json:"other_added"`
	OtherFixed    int `json:"other_fixed"`
}

// Lines splits added lines into AI-assisted and other.
type Lines struct {
	Assisted int `json:"assisted"`
	Other    int `json:"other"`
}

// Written is analysis.Written: lines added per month (YYYY-MM) and language,
// and AI-assisted lines per tool.
type Written struct {
	Months    map[string]Lines `json:"months,omitempty"`
	Languages map[string]Lines `json:"languages,omitempty"`
	Tools     map[string]int   `json:"tools,omitempty"`
}

// Tests is analysis.TestHabits.
type Tests struct {
	AssistedCommits   int `json:"assisted_commits"`
	AssistedWithTests int `json:"assisted_with_tests"`
	OtherCommits      int `json:"other_commits"`
	OtherWithTests    int `json:"other_with_tests"`
}

// Project is one repository's analysis.RepoPractices, without its label.
type Project struct {
	Languages         []string `json:"languages,omitempty"`
	CIOwned           bool     `json:"ci_owned"`
	CIGates           []string `json:"ci_gates,omitempty"`
	CITypeChecked     []string `json:"ci_type_checked,omitempty"`
	InstructionsOwned bool     `json:"instructions_owned"`
	InstructionTopics []string `json:"instruction_topics,omitempty"`
	AssistedLines     int      `json:"assisted_lines"`
	AssistedFindings  int      `json:"assisted_findings"`
	OtherLines        int      `json:"other_lines"`
	OtherFindings     int      `json:"other_findings"`
	Tests             Tests    `json:"tests"`
}

// Tool is analysis.ToolUse. Reports use only the month of the latest commit,
// so LastMonth (YYYY-MM, in the commit's own time zone) replaces its time.
type Tool struct {
	Repos     int      `json:"repos"`
	Files     int      `json:"files"`
	Commits   int      `json:"commits"`
	Lines     int      `json:"lines"`
	LastMonth string   `json:"last_month,omitempty"`
	Months    []string `json:"months,omitempty"`
}

// Commits is analysis.GitHabits.
type Commits struct {
	Commits      int `json:"commits"`
	ShortSubject int `json:"short_subject"`
	Descriptive  int `json:"descriptive"`
	Conventional int `json:"conventional"`
	WithBody     int `json:"with_body"`
}

// Design is analysis.DesignUse.
type Design struct {
	Repos     int            `json:"repos"`
	Files     int            `json:"files"`
	Libraries map[string]int `json:"libraries,omitempty"`
	Languages map[string]int `json:"languages,omitempty"`
	Months    []string       `json:"months,omitempty"`
}

// Platform is analysis.PlatformUse; Code counts code files, Config deploy and
// infrastructure files.
type Platform struct {
	Repos  int `json:"repos"`
	Files  int `json:"files"`
	Code   int `json:"code_files"`
	Config int `json:"config_files"`
}

// Sessions are sessions.Grades: counts only, never prompt text.
type Sessions struct {
	Sessions  int              `json:"sessions"`
	Tasks     map[string]int   `json:"tasks,omitempty"`
	Rules     map[string]Tally `json:"rules,omitempty"`
	Edits     int              `json:"edits"`
	Reviewed  int              `json:"reviewed"`
	EditTasks int              `json:"edit_tasks"`
	GateTasks map[string]int   `json:"gate_tasks,omitempty"`
	Style     map[string]int   `json:"style,omitempty"`
}

// Tally is how many tasks a prompting rule applied to, and how many missed it.
type Tally struct {
	Applicable int `json:"applicable"`
	Missed     int `json:"missed"`
}

// New builds an upload's facts from the scan of the Git repositories, that of
// the folders without Git (either may be empty), and the prompting grades,
// when sessions were read.
func New(git, folders analysis.Result, grades *sessions.Grades) Facts {
	f := Facts{Format: Format}
	if git.Repos > 0 || len(git.Languages) > 0 {
		s := FromResult(git)
		f.Git = &s
	}
	// A folder counts as a project even with no code in it, and its tools,
	// such as a Dockerfile, still count.
	if folders.Repos > 0 || len(folders.Languages) > 0 {
		s := FromResult(folders)
		f.Folders = &s
	}
	if grades != nil {
		s := FromGrades(*grades)
		f.Sessions = &s
	}
	return f
}

// FromResult drops a scan result's identifying fields.
func FromResult(r analysis.Result) Scan {
	s := Scan{
		Repos: r.Repos, Languages: []Language{}, OwnedLines: r.OwnedLines, AILines: r.AILines, AIFindings: r.AIFindings,
		Findings: r.Findings, MarkedLines: r.MarkedLines, MarkedByTool: r.MarkedByTool,
		Durability: Durability{r.Durability.AssistedAdded, r.Durability.AssistedFixed, r.Durability.OtherAdded, r.Durability.OtherFixed},
		Written:    Written{Months: lines(r.Written.Months), Languages: lines(r.Written.Languages), Tools: r.Written.Tools},
		Tests:      tests(r.Tests), SkippedSlow: r.SkippedSlow, SkippedUnanalyzed: r.SkippedUnanalyzed, Dismissed: r.Dismissed,
		Declared: r.Declared, Commits: Commits{r.Git.Commits, r.Git.ShortSubject, r.Git.Descriptive, r.Git.Conventional, r.Git.WithBody},
		FrameworkRepos: r.FrameworkRepos,
	}
	for _, lr := range r.Languages {
		l := Language{Name: lr.Language, Frameworks: lr.Frameworks, Files: lr.Files, OwnedLines: lr.OwnedLines,
			AssistedLines: lr.AssistedLines, AssistedFindings: lr.AssistedFindings, AssistedByRule: lr.AssistedByRule, TestLines: lr.TestLines}
		if len(lr.FrameworkUse) > 0 {
			l.FrameworkUse = map[string]Usage{}
			for k, u := range lr.FrameworkUse {
				l.FrameworkUse[k] = Usage(u)
			}
		}
		if len(lr.Findings) > 0 {
			l.FindingsByRule = map[string]int{}
			for _, f := range lr.Findings {
				l.FindingsByRule[f.Rule]++
			}
		}
		if len(lr.Idioms) > 0 {
			l.Idioms = map[string]Idiom{}
			for k, u := range lr.Idioms {
				l.Idioms[k] = Idiom(u)
			}
		}
		s.Languages = append(s.Languages, l)
	}
	for _, p := range r.PerRepo {
		s.Projects = append(s.Projects, Project{Languages: p.Languages, CIOwned: p.CIOwned, CIGates: p.CIGates, CITypeChecked: p.CITypeChecked,
			InstructionsOwned: p.InstructionsOwned, InstructionTopics: p.InstructionTopics, AssistedLines: p.AssistedLines,
			AssistedFindings: p.AssistedFindings, OtherLines: p.OtherLines, OtherFindings: p.OtherFindings, Tests: tests(p.Tests)})
	}
	// Repositories are listed by label; order them by what they hold instead,
	// so the order says nothing about their names.
	sort.SliceStable(s.Projects, func(i, j int) bool { return projectKey(s.Projects[i]) < projectKey(s.Projects[j]) })
	if len(r.Tools) > 0 {
		s.Tools = map[string]Tool{}
		for k, t := range r.Tools {
			tool := Tool{Repos: t.Repos, Files: t.Files, Commits: t.Commits, Lines: t.Lines, Months: months(t.Months)}
			if !t.Last.IsZero() {
				tool.LastMonth = t.Last.Format("2006-01")
			}
			s.Tools[k] = tool
		}
	}
	if len(r.Design) > 0 {
		s.Design = map[string]Design{}
		for k, d := range r.Design {
			s.Design[k] = Design{Repos: d.Repos, Files: d.Files, Libraries: d.Libraries, Languages: d.Languages, Months: months(d.Months)}
		}
	}
	if len(r.Platforms) > 0 {
		s.Platforms = map[string]Platform{}
		for k, p := range r.Platforms {
			s.Platforms[k] = Platform{Repos: p.Repos, Files: p.Files, Code: p.Code, Config: p.Config}
		}
	}
	return s
}

// Result turns facts back into a scan result for the report code. Findings
// carry their rule only, in rule order.
func (s Scan) Result() analysis.Result {
	r := analysis.Result{
		Repos: s.Repos, OwnedLines: s.OwnedLines, AILines: s.AILines, AIFindings: s.AIFindings, Findings: s.Findings,
		MarkedLines: s.MarkedLines, MarkedByTool: s.MarkedByTool,
		Durability: analysis.Durability{AssistedAdded: s.Durability.AssistedAdded, AssistedFixed: s.Durability.AssistedFixed,
			OtherAdded: s.Durability.OtherAdded, OtherFixed: s.Durability.OtherFixed},
		Written: analysis.Written{Months: writtenLines(s.Written.Months), Languages: writtenLines(s.Written.Languages), Tools: s.Written.Tools},
		Tests:   habits(s.Tests), SkippedSlow: s.SkippedSlow, SkippedUnanalyzed: s.SkippedUnanalyzed, Dismissed: s.Dismissed,
		Declared: s.Declared, Git: analysis.GitHabits{Commits: s.Commits.Commits, ShortSubject: s.Commits.ShortSubject,
			Descriptive: s.Commits.Descriptive, Conventional: s.Commits.Conventional, WithBody: s.Commits.WithBody},
		FrameworkRepos: s.FrameworkRepos,
	}
	for _, l := range s.Languages {
		lr := analysis.LanguageResult{Language: l.Name, Frameworks: l.Frameworks, Files: l.Files, OwnedLines: l.OwnedLines,
			AssistedLines: l.AssistedLines, AssistedFindings: l.AssistedFindings, AssistedByRule: l.AssistedByRule, TestLines: l.TestLines}
		if l.FrameworkUse != nil {
			lr.FrameworkUse = map[string]analysis.Usage{}
			for k, u := range l.FrameworkUse {
				lr.FrameworkUse[k] = analysis.Usage(u)
			}
		}
		rules := make([]string, 0, len(l.FindingsByRule))
		for rule := range l.FindingsByRule {
			rules = append(rules, rule)
		}
		sort.Strings(rules)
		for _, rule := range rules {
			for range l.FindingsByRule[rule] {
				lr.Findings = append(lr.Findings, analysis.Finding{Rule: rule})
			}
		}
		if l.Idioms != nil {
			lr.Idioms = map[string]analysis.IdiomUse{}
			for k, u := range l.Idioms {
				lr.Idioms[k] = analysis.IdiomUse(u)
			}
		}
		r.Languages = append(r.Languages, lr)
	}
	for _, p := range s.Projects {
		r.PerRepo = append(r.PerRepo, analysis.RepoPractices{Languages: p.Languages, CIOwned: p.CIOwned, CIGates: p.CIGates,
			CITypeChecked: p.CITypeChecked, InstructionsOwned: p.InstructionsOwned, InstructionTopics: p.InstructionTopics,
			AssistedLines: p.AssistedLines, AssistedFindings: p.AssistedFindings, OtherLines: p.OtherLines, OtherFindings: p.OtherFindings,
			Tests: habits(p.Tests)})
	}
	if s.Tools != nil {
		r.Tools = map[string]analysis.ToolUse{}
		for k, t := range s.Tools {
			var last time.Time
			if m, err := time.Parse("2006-01", t.LastMonth); err == nil {
				last = m.AddDate(0, 0, 14) // mid-month, so any time zone keeps the month
			}
			r.Tools[k] = analysis.ToolUse{Repos: t.Repos, Files: t.Files, Commits: t.Commits, Lines: t.Lines, Last: last, Months: monthSet(t.Months)}
		}
	}
	if s.Design != nil {
		r.Design = map[string]analysis.DesignUse{}
		for k, d := range s.Design {
			r.Design[k] = analysis.DesignUse{Usage: analysis.Usage{Repos: d.Repos, Files: d.Files}, Libraries: d.Libraries,
				Languages: d.Languages, Months: monthSet(d.Months)}
		}
	}
	if s.Platforms != nil {
		r.Platforms = map[string]analysis.PlatformUse{}
		for k, p := range s.Platforms {
			r.Platforms[k] = analysis.PlatformUse{Usage: analysis.Usage{Repos: p.Repos, Files: p.Files}, Code: p.Code, Config: p.Config}
		}
	}
	return r
}

// FromGrades turns prompting grades into their facts.
func FromGrades(g sessions.Grades) Sessions {
	s := Sessions{Sessions: g.Sessions, Tasks: g.Tasks, Edits: g.Edits, Reviewed: g.Reviewed, EditTasks: g.EditTasks,
		GateTasks: g.GateTasks, Style: g.Style}
	if g.Rules != nil {
		s.Rules = map[string]Tally{}
		for k, t := range g.Rules {
			s.Rules[k] = Tally{Applicable: t.Applicable, Missed: t.Missed}
		}
	}
	return s
}

// projectKey orders projects by their languages, size, findings, and gates;
// numbers are zero-padded so string order is numeric order.
func projectKey(p Project) string {
	return fmt.Sprintf("%s|%012d|%012d|%s", strings.Join(p.Languages, ","), p.AssistedLines+p.OtherLines,
		p.AssistedFindings+p.OtherFindings, strings.Join(p.CIGates, ","))
}

func tests(t analysis.TestHabits) Tests {
	return Tests{t.AssistedCommits, t.AssistedWithTests, t.OtherCommits, t.OtherWithTests}
}

func habits(t Tests) analysis.TestHabits {
	return analysis.TestHabits{AssistedCommits: t.AssistedCommits, AssistedWithTests: t.AssistedWithTests,
		OtherCommits: t.OtherCommits, OtherWithTests: t.OtherWithTests}
}

func lines(m map[string]analysis.WrittenLines) map[string]Lines {
	if len(m) == 0 {
		return nil
	}
	out := map[string]Lines{}
	for k, w := range m {
		out[k] = Lines{w.Assisted, w.Other}
	}
	return out
}

func writtenLines(m map[string]Lines) map[string]analysis.WrittenLines {
	out := map[string]analysis.WrittenLines{}
	for k, l := range m {
		out[k] = analysis.WrittenLines{Assisted: l.Assisted, Other: l.Other}
	}
	return out
}

func months(m analysis.Months) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for month := range m {
		out = append(out, month)
	}
	sort.Strings(out)
	return out
}

func monthSet(ms []string) analysis.Months {
	out := analysis.Months{}
	for _, m := range ms {
		out[m] = true
	}
	return out
}
