package career

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Pack is what `urfluency career draft` sends: roles, features in plain words,
// technologies, dates, and the user's confirmed facts. It has no code, diffs,
// file paths, repository names, URLs, or email addresses; ValidatePack refuses
// one that looks like it does.
type Pack struct {
	Format   string        `json:"format"`
	Kind     string        `json:"kind"`
	Roles    []PackRole    `json:"roles"`
	Features []PackFeature `json:"features"`
	Facts    []PackFact    `json:"facts"`
	// Side are features of personal work the user chose to mention in About.
	Side   []PackFeature `json:"side,omitempty"`
	Skills []string      `json:"skills"`
	Target *Target       `json:"target,omitempty"`
	// ExactFigures shows money as the user's exact figure, not a range.
	ExactFigures bool `json:"exact_figures,omitempty"`
}

// PackRole is one role, official title first.
type PackRole struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Note    string `json:"note,omitempty"`
	Company string `json:"company"`
	Start   string `json:"start"`
	End     string `json:"end,omitempty"`
}

// PackFeature is a feature in plain words. Share is the user's percentage of
// the repository's commits.
type PackFeature struct {
	ID           string   `json:"id"`
	RoleID       string   `json:"role"`
	Summary      string   `json:"summary"`
	Technologies []string `json:"technologies,omitempty"`
	Commits      int      `json:"commits"`
	Share        int      `json:"share"`
	Start        string   `json:"start"`
	End          string   `json:"end"`
}

// PackFact is a confirmed fact.
type PackFact struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	RoleID string `json:"role,omitempty"`
	Text   string `json:"text"`
}

// AssistRequest is what the CLI sends for Vertex to describe features, word the
// questions, and suggest generic names. Internal names arrive only as tokens
// ("NAME1"), with the redacted text around them, never as themselves.
type AssistRequest struct {
	Format    string          `json:"format"`
	Features  []AssistFeature `json:"features"`
	Questions []Question      `json:"questions"`
	Names     []AssistName    `json:"names"`
}

// AssistFeature is a feature's redacted commit subjects.
type AssistFeature struct {
	ID           string   `json:"id"`
	Subjects     []string `json:"subjects"`
	Technologies []string `json:"technologies,omitempty"`
	Purpose      string   `json:"purpose,omitempty"`
}

// AssistName is a name's token and the redacted text it appears in.
type AssistName struct {
	Token   string `json:"token"`
	Context string `json:"context"`
}

// AssistAnswer is Vertex's checked answer.
type AssistAnswer struct {
	Features  []FeatureText  `json:"features"`
	Questions []QuestionText `json:"questions"`
	Names     []NameText     `json:"names"`
}

// FeatureText describes a feature in plain words.
type FeatureText struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

// QuestionText words a question.
type QuestionText struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

// NameText suggests a generic description for a name's token.
type NameText struct {
	Token   string `json:"token"`
	Generic string `json:"generic"`
}

// Draft is a checked draft. Every sentence cites the features ("f3") or facts
// ("q2") it rests on.
type Draft struct {
	Format   string `json:"format"`
	Kind     string `json:"kind"`
	Model    string `json:"model,omitempty"`
	Headline string `json:"headline,omitempty"`
	// About is LinkedIn's About, in paragraphs; Summary is a resume's.
	About        [][]Sentence `json:"about,omitempty"`
	Summary      []Sentence   `json:"summary,omitempty"`
	Competencies []string     `json:"competencies,omitempty"`
	Skills       []string     `json:"skills,omitempty"`
	// Implied are skills the work implies but no evidence names, for the
	// user to keep or drop.
	Implied []string    `json:"implied,omitempty"`
	Roles   []RoleDraft `json:"roles"`
	// Dropped are sentences the check removed, with why.
	Dropped []Dropped `json:"dropped,omitempty"`
}

// Sentence is one cited sentence.
type Sentence struct {
	Text  string   `json:"text"`
	Cites []string `json:"cites"`
}

// RoleDraft is one role's entry: paragraphs for LinkedIn, bullets for a resume.
type RoleDraft struct {
	RoleID     string       `json:"role"`
	Paragraphs [][]Sentence `json:"paragraphs,omitempty"`
	Further    string       `json:"further,omitempty"`
	Skills     []string     `json:"skills,omitempty"`
	Bullets    []Bullet     `json:"bullets,omitempty"`
}

// Bullet is a resume bullet, ranked by its evidence. Keep marks it for the
// one-page version.
type Bullet struct {
	Sentence
	Rank int    `json:"rank"`
	Keep bool   `json:"keep"`
	Why  string `json:"why"`
}

// Dropped is a sentence the check removed.
type Dropped struct {
	RoleID string `json:"role,omitempty"`
	Text   string `json:"text"`
	Why    string `json:"why"`
}

// LinkedIn's limits, in characters.
const (
	HeadlineLimit = 220
	AboutLimit    = 2600
	RoleLimit     = 2000
)

// MaxPackBytes bounds an encoded pack or assist request.
const MaxPackBytes = 256 << 10

var (
	emailRe = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	urlRe   = regexp.MustCompile(`(?i)\b(https?|ssh|git|ftp)://|\bwww\.[a-z0-9-]+\.|\bgit@`)
	pathRe  = regexp.MustCompile(`(^|[^A-Za-z0-9_.-])(/Users/|/home/|/root/|~/|/tmp/|/var/|/opt/|/etc/|/private/|/mnt/|/Volumes/|[A-Za-z]:[\\/])`)
	hashRe  = regexp.MustCompile(`\b[0-9a-f]{7,64}\b`)
	ipRe    = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	idRe    = regexp.MustCompile(`^[a-z]{1,4}[0-9]{1,4}$`)
	monthRe = regexp.MustCompile(`^(19|20)\d\d-(0[1-9]|1[0-2])$`)
	tokenRe = regexp.MustCompile(`\bNAME[0-9]{1,3}\b`)
)

// ErrIdentifying marks a pack refused for carrying identifying text.
var ErrIdentifying = errors.New("career pack carries identifying text")

// ErrUnusable marks a model answer that arrived, and so was paid for, but
// can't be used: cut off, not JSON, or with nothing that passed the checks.
var ErrUnusable = errors.New("the model's answer could not be used")

// identifying names what in s would identify code, people, or systems, or
// returns "". Hashes count only when they hold a digit and a letter, so words
// like "facade" pass.
func identifying(s string) string {
	switch {
	case emailRe.MatchString(s):
		return "an email address"
	case urlRe.MatchString(s):
		return "a URL"
	case pathRe.MatchString(s):
		return "a local path"
	case ipRe.MatchString(s):
		return "an IP address"
	case secretRe.MatchString(s):
		return "a token-shaped string"
	}
	for _, h := range hashRe.FindAllString(s, -1) {
		if strings.ContainsAny(h, "0123456789") && strings.ContainsAny(h, "abcdef") && len(h) >= 12 {
			return "a commit hash"
		}
	}
	return ""
}

// Validate is ValidatePack(p), so a pack carries its own schema check.
func (p Pack) Validate() error { return ValidatePack(p) }

// ValidatePack checks a pack's shape and refuses identifying text in any of its
// strings.
func ValidatePack(p Pack) error {
	if p.Format != Format {
		return fmt.Errorf("career pack format %q, want %q", p.Format, Format)
	}
	if p.Kind != LinkedIn && p.Kind != Resume {
		return fmt.Errorf("career pack kind %q", p.Kind)
	}
	if len(p.Roles) == 0 || len(p.Roles) > 30 {
		return errors.New("a career pack needs 1 to 30 roles")
	}
	if len(p.Features)+len(p.Side) > 400 || len(p.Facts) > 300 || len(p.Skills) > 80 {
		return errors.New("career pack is too large")
	}
	roles := map[string]bool{}
	for _, r := range p.Roles {
		if !idRe.MatchString(r.ID) || !monthRe.MatchString(r.Start) || (r.End != "" && !monthRe.MatchString(r.End)) {
			return fmt.Errorf("role %q: bad ID or dates", r.ID)
		}
		roles[r.ID] = true
		if err := texts("role "+r.ID, 120, r.Title, r.Note, r.Company); err != nil {
			return err
		}
	}
	for _, f := range append(append([]PackFeature{}, p.Features...), p.Side...) {
		if !idRe.MatchString(f.ID) || (f.RoleID != "side" && !roles[f.RoleID]) || !monthRe.MatchString(f.Start) || !monthRe.MatchString(f.End) {
			return fmt.Errorf("feature %q: bad ID, role, or dates", f.ID)
		}
		if f.Share < 0 || f.Share > 100 || f.Commits < 0 {
			return fmt.Errorf("feature %q: bad counts", f.ID)
		}
		if err := texts("feature "+f.ID, 400, append([]string{f.Summary}, f.Technologies...)...); err != nil {
			return err
		}
	}
	for _, f := range p.Facts {
		if !idRe.MatchString(f.ID) || (f.RoleID != "" && !roles[f.RoleID]) {
			return fmt.Errorf("fact %q: bad ID or role", f.ID)
		}
		if err := texts("fact "+f.ID, 600, f.Kind, f.Text); err != nil {
			return err
		}
	}
	if err := texts("skills", 60, p.Skills...); err != nil {
		return err
	}
	// Every sentence of a draft must cite a role's feature or fact, so a pack
	// with none can only come back empty.
	cited := false
	for _, f := range p.Features {
		cited = cited || f.Summary != ""
	}
	for _, f := range p.Facts {
		cited = cited || f.RoleID != "" && f.Text != ""
	}
	if !cited {
		return errors.New("the pack has no features or answers for any role to draft from; approve repositories on the map or answer the questions")
	}
	return size(p)
}

// Validate is ValidateAssist(a), so a request carries its own schema check.
func (a AssistRequest) Validate() error { return ValidateAssist(a) }

// ValidateAssist checks an assist request as ValidatePack checks a pack, and
// refuses one whose names are anything but tokens.
func ValidateAssist(a AssistRequest) error {
	if a.Format != Format {
		return fmt.Errorf("assist format %q, want %q", a.Format, Format)
	}
	if len(a.Features) > 400 || len(a.Questions) > 300 || len(a.Names) > 100 {
		return errors.New("assist request is too large")
	}
	for _, f := range a.Features {
		if !idRe.MatchString(f.ID) || len(f.Subjects) > 60 {
			return fmt.Errorf("feature %q: bad ID or too many subjects", f.ID)
		}
		if err := texts("feature "+f.ID, 300, append(append([]string{f.Purpose}, f.Subjects...), f.Technologies...)...); err != nil {
			return err
		}
	}
	for _, q := range a.Questions {
		if !idRe.MatchString(q.ID) {
			return fmt.Errorf("question %q: bad ID", q.ID)
		}
		if err := texts("question "+q.ID, 300, q.Kind, q.Text); err != nil {
			return err
		}
	}
	for _, n := range a.Names {
		if !tokenRe.MatchString(n.Token) || n.Token != tokenRe.FindString(n.Token) {
			return fmt.Errorf("name %q is not a token", n.Token)
		}
		if err := texts("name "+n.Token, 400, n.Context); err != nil {
			return err
		}
	}
	return size(a)
}

// texts refuses strings that are too long or identifying.
func texts(at string, limit int, ss ...string) error {
	for _, s := range ss {
		if len(s) > limit {
			return fmt.Errorf("%s: text over %d characters", at, limit)
		}
		if why := identifying(s); why != "" {
			return fmt.Errorf("%w: %s in %s", ErrIdentifying, why, at)
		}
	}
	return nil
}

func size(v any) error {
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(v); err != nil {
		return err
	}
	if b.Len() > MaxPackBytes {
		return fmt.Errorf("over %d bytes", MaxPackBytes)
	}
	return nil
}
