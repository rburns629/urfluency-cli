// Package career is the contract for `urfluency career`, which turns a user's
// own Git history into LinkedIn and resume drafts. It holds three things:
//
//   - the types the CLI, the private engine, and the API share;
//   - reading a LinkedIn data export (linkedin.go);
//   - the privacy layer: what may leave the machine and in what form. Redact
//     strips identifying text, and ValidatePack and ValidateAssist refuse
//     anything that still looks identifying (redact.go, pack.go).
//
// The analysis itself (grouping commits into features, placing work under
// roles, checking claims, asking questions, and building the pack) is the
// engine's, registered with Register. The community build registers none, so
// `urfluency career` says it needs the official build.
package career

import "time"

// Format versions packs, assist requests, and drafts.
const Format = "1"

// Kinds of draft.
const (
	LinkedIn = "linkedin"
	Resume   = "resume"
)

// Position is one role in the user's timeline, from a LinkedIn export or
// entered by hand. Start and End are months, "2024-03"; End is "" for a role
// held now.
type Position struct {
	ID          string `json:"id"` // "r1", "r2", ... in the order the export lists them
	Title       string `json:"title"`
	Company     string `json:"company"`
	Description string `json:"description,omitempty"`
	Start       string `json:"start"`
	End         string `json:"end,omitempty"`
	// Official is the title on the employment record when it differs from
	// Title; drafts lead with it. Note is a short description of the work in
	// parentheses after it, such as "Software Engineer".
	Official string `json:"official,omitempty"`
	Note     string `json:"note,omitempty"`
}

// Profile is what the CLI reads from a LinkedIn export: the name, headline,
// summary, and positions, and nothing else of the archive.
type Profile struct {
	Name      string     `json:"name"`
	Headline  string     `json:"headline,omitempty"`
	Summary   string     `json:"summary,omitempty"`
	Positions []Position `json:"positions"`
}

// Evidence is what the CLI collected from the user's repositories. It stays on
// the machine: it holds repository names, folders, and commit subjects.
type Evidence struct {
	Emails []string       `json:"emails"`
	Repos  []RepoEvidence `json:"repos"`
}

// RepoEvidence is one repository.
type RepoEvidence struct {
	ID     string `json:"id"`     // "g1", "g2", ...
	Name   string `json:"name"`   // the folder's name
	Folder string `json:"folder"` // relative to the folder career map was run on
	// Purpose is the README's first paragraph or the manifest's description.
	Purpose      string   `json:"purpose,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
	// Commits are the user's own non-merge commits.
	Commits      []Commit `json:"commits"`
	TotalCommits int      `json:"total_commits"`
	// Root is the first commit's hash, which copies of one history share.
	Root string `json:"root,omitempty"`
	// Files is how many files are tracked, to tell a skeleton from a project.
	Files int `json:"files"`
}

// Commit is one of the user's commits.
type Commit struct {
	Time    time.Time `json:"time"`
	Subject string    `json:"subject"`
	Email   string    `json:"email"`
}

// Feature is a group of commits about one piece of work, which the engine
// forms from commit subjects.
type Feature struct {
	ID     string `json:"id"` // "f1", "f2", ...
	RepoID string `json:"repo"`
	RoleID string `json:"role,omitempty"`
	// Title is the engine's own wording; Summary replaces it once Vertex
	// describes the feature (on Pro, with drafting on).
	Title    string   `json:"title"`
	Summary  string   `json:"summary,omitempty"`
	Subjects []string `json:"subjects"`
	Commits  int      `json:"commits"`
	// Share is the user's percentage of the repository's commits, and
	// Purpose the repository's, which stays on the machine.
	Share        int       `json:"share"`
	Purpose      string    `json:"purpose,omitempty"`
	Technologies []string  `json:"technologies,omitempty"`
	Start        time.Time `json:"start"`
	End          time.Time `json:"end"`
}

// Kinds of decision.
const (
	DecideSplit    = "split"    // a repository's commits cross a role boundary
	DecideFolder   = "folder"   // the folder suggests one role, the dates another
	DecidePersonal = "personal" // personal work outside the work folders
	DecideThin     = "thin"     // a role with little in Git
	DecideCopy     = "copy"     // the same history in more than one folder
	DecideSkeleton = "skeleton" // little beyond scaffolding
	DecideClone    = "clone"    // someone else's project with few of the user's commits
)

// Decision is something the map asks the user to settle.
type Decision struct {
	ID      string   `json:"id"`
	Kind    string   `json:"kind"`
	RepoID  string   `json:"repo,omitempty"`
	RoleID  string   `json:"role,omitempty"`
	Title   string   `json:"title"`
	Detail  string   `json:"detail"`
	Options []string `json:"options"`
	// Recommended is the option the engine would pick; Choice is the user's,
	// -1 until they choose.
	Recommended int `json:"recommended"`
	Choice      int `json:"choice"`
}

// Placement is a share of a repository's commits under one role.
type Placement struct {
	RepoID  string    `json:"repo"`
	RoleID  string    `json:"role"` // "" when left out, "side" for a side project
	Commits int       `json:"commits"`
	Start   time.Time `json:"start"`
	End     time.Time `json:"end"`
}

// Claim statuses.
const (
	Supported   = "supported"
	NeedsAnswer = "needs_answer"
	Conflicts   = "conflicts"
	NoEvidence  = "no_evidence"
)

// Claim is a statement in the user's current profile, checked against the
// evidence.
type Claim struct {
	RoleID string `json:"role,omitempty"`
	Text   string `json:"text"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// Name is an internal name found in commits or READMEs. Token stands in for it
// in anything sent; Generic replaces it in drafts. Public names, such as a
// product anyone can buy, are kept.
type Name struct {
	Token     string `json:"token"` // "NAME1", ...
	Found     string `json:"found"`
	Generic   string `json:"generic"`
	Public    bool   `json:"public"`
	Confirmed bool   `json:"confirmed"`
}

// Map is the timeline: roles, where each repository's work goes, what the user
// must decide, the claim check, and the names to generalize.
type Map struct {
	Format     string      `json:"format"`
	Roles      []Position  `json:"roles"`
	Placements []Placement `json:"placements"`
	Decisions  []Decision  `json:"decisions"`
	Features   []Feature   `json:"features"`
	Claims     []Claim     `json:"claims"`
	Names      []Name      `json:"names"`
	Approved   bool        `json:"approved"`
}

// Pending reports whether a decision is still open.
func (m Map) Pending() int {
	n := 0
	for _, d := range m.Decisions {
		if d.Choice < 0 {
			n++
		}
	}
	return n
}

// Kinds of fact and question.
const (
	FactOwnership = "ownership"
	FactShipped   = "shipped"
	FactScale     = "scale"
	FactOutcome   = "outcome"
	FactPartner   = "partner"
	FactUnseen    = "unseen" // work Git can't see: reviews, mentoring, escalations
)

// Question is something Git can't show, asked once per item.
type Question struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	RoleID    string `json:"role,omitempty"`
	FeatureID string `json:"feature,omitempty"`
	Text      string `json:"text"`
}

// Fact is the user's answer to a question. An unanswered question has no fact,
// and its claim stays out of drafts.
type Fact struct {
	ID        string `json:"id"` // the question's ID
	Kind      string `json:"kind"`
	RoleID    string `json:"role,omitempty"`
	FeatureID string `json:"feature,omitempty"`
	Text      string `json:"text"`
}

// Target is the structure learned from a target profile or resume. Only these
// rules are used, never the target's text.
type Target struct {
	Kind              string   `json:"kind"` // LinkedIn or Resume
	ParagraphsPerRole int      `json:"paragraphs_per_role,omitempty"`
	BulletsPerRole    int      `json:"bullets_per_role,omitempty"`
	MinChars          int      `json:"min_chars,omitempty"`
	MaxChars          int      `json:"max_chars,omitempty"`
	Opening           string   `json:"opening,omitempty"` // "noun phrase", "verb", or "first person"
	SentenceWords     int      `json:"sentence_words,omitempty"`
	CrossTeamSecond   bool     `json:"cross_team_second,omitempty"`
	FurtherLine       bool     `json:"further_line,omitempty"`
	SkillsPerRole     int      `json:"skills_per_role,omitempty"`
	Sections          []string `json:"sections,omitempty"` // resume section order
}

// Engine is the analysis `urfluency career` runs. The private engine provides
// it; the community build has none.
type Engine interface {
	// Analyze groups the evidence into features, places them under the
	// profile's roles by commit date, lists the decisions and internal names,
	// and checks the profile's claims.
	Analyze(p Profile, ev Evidence) Map
	// Resolve recomputes the placements and features' roles from the
	// decisions the user made.
	Resolve(m Map, ev Evidence) Map
	// Questions lists what Git can't show, for the map as resolved.
	Questions(m Map) []Question
	// LearnTarget derives structure rules from a target's text.
	LearnTarget(kind, text string) Target
	// BuildPack assembles what a draft needs. The CLI redacts and validates
	// it before anything is sent.
	BuildPack(kind string, m Map, facts []Fact, target *Target) Pack
	// BuildAssist assembles what Vertex needs to describe features, word
	// questions, and suggest generic names. The CLI redacts and validates it.
	BuildAssist(m Map, qs []Question) AssistRequest
}

var engine Engine

// Register sets the engine; the official build's engine calls it from init.
func Register(e Engine) { engine = e }

// Registered returns the engine, or nil in the community build.
func Registered() Engine { return engine }
