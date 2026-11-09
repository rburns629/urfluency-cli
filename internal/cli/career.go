package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/roburns/urfluency-cli/career"
	"github.com/roburns/urfluency-cli/gitdata"
)

// `urfluency career` turns the user's own Git history into LinkedIn and resume
// drafts. Every step needs a signed-in account; the steps before drafting are
// free. The analysis is the engine's (package career); this file collects the
// evidence, keeps the state on this machine, and redacts and validates
// anything before it is sent. Vertex AI is used only on Pro with drafting
// turned on: to describe features, word the questions, and suggest generic
// names during the map step, and to write the drafts.
//
// State lives in <config dir>/urfluency/career/, readable only by the user:
//   profile.json    what was read from the LinkedIn export
//   target-*.json   structure rules learned from a target
//   evidence.json   repositories, folders, and commit subjects
//   map.json        the timeline and the user's decisions
//   wording.json    Vertex's wording of the questions
//   facts.json      the user's answers
//   drafts/         drafts as the API returned them, and saved resumes

const careerSteps = "import, target, map, questions, show, draft, or review"

func careerCmd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: career needs a step: %s", errUsage, careerSteps)
	}
	switch args[0] {
	case "import":
		return careerImport(ctx, args[1:], stdout)
	case "target":
		return careerTarget(ctx, args[1:], stdout)
	case "map":
		return careerMap(ctx, args[1:], stdout, stderr)
	case "questions":
		return careerQuestions(ctx, args[1:], stdout)
	case "show":
		return careerShow(ctx, args[1:], stdout)
	case "draft":
		return careerDraft(ctx, args[1:], stdout)
	case "review":
		return careerReview(ctx, args[1:], stdout)
	}
	return fmt.Errorf("%w: unknown career step %q; use %s", errUsage, args[0], careerSteps)
}

// --- account --------------------------------------------------------------------

// careerAccount is the account's career status from GET /v1/career.
type careerAccount struct {
	creds    credentials
	Plan     string `json:"plan"`
	Drafting bool   `json:"drafting"`
	Left     int    `json:"drafts_left"`
	PerWeek  int    `json:"drafts_per_week"`
}

// vertex reports whether the account may use Vertex AI: Pro with drafting on.
func (a careerAccount) vertex() bool { return a.Plan == "pro" && a.Drafting }

var errNoEngine = errors.New("urfluency career needs the official build, which includes the engine: brew install roburns/tap/urfluency")

// careerGate checks that this build has the engine and that the CLI is signed
// in to an account the API accepts. It runs before every career step.
func careerGate(ctx context.Context) (careerAccount, career.Engine, error) {
	eng := career.Registered()
	if eng == nil {
		return careerAccount{}, nil, errNoEngine
	}
	c, err := loadCredentials()
	if err != nil {
		return careerAccount{}, nil, fmt.Errorf("urfluency career needs a signed-in account (free to create): %w", err)
	}
	if _, err := c.privateKey(); err != nil {
		return careerAccount{}, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	a := careerAccount{creds: c}
	status, code, err := signedJSON(ctx, http.MethodGet, c.API+"/v1/career", c, nil, &a)
	switch {
	case err != nil:
		return careerAccount{}, nil, fmt.Errorf("could not reach %s to check your account, which urfluency career needs: %w", c.API, err)
	case status == http.StatusUnauthorized:
		return careerAccount{}, nil, loginRefused(code)
	case status/100 != 2:
		return careerAccount{}, nil, fmt.Errorf("checking your account: %s (%d)", code, status)
	}
	a.creds = c
	return a, eng, nil
}

// --- state ------------------------------------------------------------------------

func careerDir() (string, error) {
	settings, err := settingsPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(settings), "career"), nil
}

// readState decodes a state file; a missing one returns fs.ErrNotExist.
func readState(name string, v any) error {
	dir, err := careerDir()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	return nil
}

// writeState writes a state file as JSON.
func writeState(name string, v any) (string, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return writeStateBytes(name, append(data, '\n'))
}

// writeStateBytes writes a state file atomically, readable only by the user.
func writeStateBytes(name string, data []byte) (string, error) {
	dir, err := careerDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	return path, os.Rename(tmp.Name(), path)
}

func loadProfile() (career.Profile, error) {
	var p career.Profile
	if err := readState("profile.json", &p); errors.Is(err, fs.ErrNotExist) {
		return p, errors.New("import your LinkedIn export first: urfluency career import EXPORT.zip")
	} else if err != nil {
		return p, err
	}
	return p, nil
}

func loadMap(approved bool) (career.Map, career.Evidence, error) {
	var m career.Map
	var ev career.Evidence
	if err := readState("map.json", &m); errors.Is(err, fs.ErrNotExist) {
		return m, ev, errors.New("map your work first: urfluency career map [folder]")
	} else if err != nil {
		return m, ev, err
	}
	if err := readState("evidence.json", &ev); err != nil {
		return m, ev, err
	}
	if approved && !m.Approved {
		return m, ev, errors.New("approve the map first: urfluency career map [folder], then Approve on its page")
	}
	return m, ev, nil
}

// --- import and target --------------------------------------------------------

func careerImport(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("%w: career import takes the LinkedIn export's zip", errUsage)
	}
	if _, _, err := careerGate(ctx); err != nil {
		return err
	}
	p, err := career.ReadExport(args[0])
	if err != nil {
		return err
	}
	// Official titles entered on the map page survive a new import.
	var old career.Profile
	if readState("profile.json", &old) == nil {
		for i, pos := range p.Positions {
			for _, o := range old.Positions {
				if o.Title == pos.Title && o.Start == pos.Start {
					p.Positions[i].Official, p.Positions[i].Note = o.Official, o.Note
				}
			}
		}
	}
	path, err := writeState("profile.json", p)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Read %s with titles, companies, and dates, and your headline and summary.\n", count(len(p.Positions), "position"))
	fmt.Fprintln(stdout, "Only Profile.csv and Positions.csv were opened; nothing else in the export was read, and nothing was sent.")
	fmt.Fprintf(stdout, "Saved to %s\nNext: urfluency career map [folder with your repositories]\n", path)
	return nil
}

// maxTarget bounds a target file.
const maxTarget = 1 << 20

func careerTarget(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("career target", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	resume := fs.Bool("resume", false, "")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("%w: career target takes a text file of the profile or resume to follow", errUsage)
	}
	_, eng, err := careerGate(ctx)
	if err != nil {
		return err
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxTarget+1))
	if err != nil {
		return err
	}
	if len(data) > maxTarget {
		return errors.New("the target is over 1 MB; paste only the profile or resume text")
	}
	kind := kindOf(*resume)
	t := eng.LearnTarget(kind, string(data))
	path, err := writeState("target-"+kind+".json", t)
	if err != nil {
		return err
	}
	if kind == career.Resume {
		fmt.Fprintf(stdout, "Learned: sections %s; about %d bullets per role, %d to %d characters each.\n",
			strings.Join(t.Sections, ", "), t.BulletsPerRole, t.MinChars, t.MaxChars)
	} else {
		fmt.Fprintf(stdout, "Learned: %d paragraphs per role, %d to %d characters, entries open with a %s, about %d words a sentence.\n",
			t.ParagraphsPerRole, t.MinChars, t.MaxChars, t.Opening, t.SentenceWords)
	}
	fmt.Fprintf(stdout, "Only these rules are kept, in %s; the target's text was not saved or sent. Edit the file to change them.\n", path)
	return nil
}

func kindOf(resume bool) string {
	if resume {
		return career.Resume
	}
	return career.LinkedIn
}

// --- map --------------------------------------------------------------------------

func careerMap(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("career map", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var authors, excludes stringList
	fs.Var(&authors, "author", "")
	fs.Var(&excludes, "exclude", "")
	noBrowser := fs.Bool("no-browser", false, "")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	root, err := onePath(fs, "career map")
	if err != nil {
		return err
	}
	acct, eng, err := careerGate(ctx)
	if err != nil {
		return err
	}
	profile, err := loadProfile()
	if err != nil {
		return err
	}
	if root, err = filepath.Abs(root); err != nil {
		return err
	}
	repos, _, err := findProjects(root, excludes)
	if err != nil {
		return err
	}
	if len(repos) == 0 {
		return fmt.Errorf("no Git repositories under %s", root)
	}
	id := detectIdentity(ctx, repos, authors)
	fmt.Fprintln(stderr, describeIdentity(id, len(repos)))
	ev := collectEvidence(ctx, root, repos, id.Emails)
	m := eng.Analyze(profile, ev)
	var old career.Map
	if readState("map.json", &old) == nil {
		carryOver(&m, old)
		m = eng.Resolve(m, ev)
	}
	if acct.vertex() {
		if err := assist(ctx, acct, eng, &m, ev); err != nil {
			fmt.Fprintf(stderr, "Vertex AI could not help this time (%v); the map uses the engine's own wording.\n", err)
		}
	}
	if _, err := writeState("evidence.json", ev); err != nil {
		return err
	}
	if _, err := writeState("map.json", m); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Placed %d %s by commit date. To settle on the page: %s, and %s to generalize; %s in your profile checked.\n",
		len(ev.Repos), plural(len(ev.Repos), "repository", "repositories"), count(m.Pending(), "decision"), count(len(m.Names), "internal name"),
		count(len(m.Claims), "claim"))
	return serveMap(ctx, stdout, eng, profile, ev, m, *noBrowser)
}

// carryOver keeps the user's earlier decisions and names on a rebuilt map.
func carryOver(m *career.Map, old career.Map) {
	prev := map[string]career.Decision{}
	for _, d := range old.Decisions {
		prev[d.Kind+"\x00"+d.Title] = d
	}
	for i, d := range m.Decisions {
		if o, ok := prev[d.Kind+"\x00"+d.Title]; ok && slices.Equal(o.Options, d.Options) && o.Choice >= 0 {
			m.Decisions[i].Choice = o.Choice
		}
	}
	names := map[string]career.Name{}
	for _, n := range old.Names {
		names[n.Found] = n
	}
	for i, n := range m.Names {
		if o, ok := names[n.Found]; ok {
			m.Names[i].Generic, m.Names[i].Public, m.Names[i].Confirmed = o.Generic, o.Public, o.Confirmed
		}
	}
	summaries := map[string]string{}
	for _, f := range old.Features {
		if f.Summary != "" {
			summaries[f.RepoID+"\x00"+f.RoleID+"\x00"+f.Title] = f.Summary
		}
	}
	for i, f := range m.Features {
		m.Features[i].Summary = summaries[f.RepoID+"\x00"+f.RoleID+"\x00"+f.Title]
	}
}

// assist asks Vertex, through the API, to describe the features, word the
// questions, and suggest generic names. Names leave the machine only as
// tokens.
func assist(ctx context.Context, acct careerAccount, eng career.Engine, m *career.Map, ev career.Evidence) error {
	qs := eng.Questions(*m)
	req := eng.BuildAssist(*m, qs)
	career.RedactAssist(&req, career.WithRepositories(career.ForAssist(m.Names), ev))
	if err := career.ValidateAssist(req); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	var a career.AssistAnswer
	status, code, err := signedJSONVia(ctx, slowClient, http.MethodPost, acct.creds.API+"/v1/career/assist", acct.creds, req, &a)
	switch {
	case err != nil:
		return err
	case status/100 != 2:
		return fmt.Errorf("%s (%d)", code, status)
	}
	summaries := map[string]string{}
	for _, f := range a.Features {
		summaries[f.ID] = f.Summary
	}
	for i, f := range m.Features {
		if s := summaries[f.ID]; s != "" {
			m.Features[i].Summary = s
		}
	}
	generic := map[string]string{}
	for _, n := range a.Names {
		generic[n.Token] = n.Generic
	}
	for i, n := range m.Names {
		if g := generic[n.Token]; g != "" && !n.Confirmed {
			m.Names[i].Generic = g
		}
	}
	wording := map[string]career.Question{}
	byID := map[string]career.Question{}
	for _, q := range qs {
		byID[q.ID] = q
	}
	for _, t := range a.Questions {
		if q, ok := byID[t.ID]; ok {
			wording[questionKey(q)] = career.Question{ID: q.ID, Kind: q.Kind, RoleID: q.RoleID, FeatureID: q.FeatureID, Text: t.Text}
		}
	}
	_, err = writeState("wording.json", wording)
	return err
}

// questionKey identifies a question across rebuilt maps, whose question and
// feature IDs change: by its kind, role, and the engine's own wording, which
// names the feature by its topic. Its figures are left out, so an answer about
// ownership survives new commits that change "you made 34% of the commits".
func questionKey(q career.Question) string {
	return q.Kind + "\x00" + q.RoleID + "\x00" + keyDigits.ReplaceAllString(q.Text, "#")
}

var keyDigits = regexp.MustCompile(`\d+`)

// --- evidence -------------------------------------------------------------------

// collectEvidence reads each repository's purpose, technologies, and the
// user's commits. Repositories whose history can't be read are skipped.
func collectEvidence(ctx context.Context, root string, repos, emails []string) career.Evidence {
	sort.Strings(repos)
	out := make([]*career.RepoEvidence, len(repos))
	sem := make(chan struct{}, runtime.NumCPU())
	var wg sync.WaitGroup
	for i, dir := range repos {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			r := gitdata.Repo{Dir: dir}
			commits, err := r.AuthoredCommits(ctx, emails)
			if err != nil {
				return
			}
			rel, _ := filepath.Rel(root, dir)
			ev := &career.RepoEvidence{Name: filepath.Base(dir), Folder: filepath.ToSlash(rel), Purpose: purpose(dir)}
			for _, c := range commits {
				ev.Commits = append(ev.Commits, career.Commit{Time: c.Time, Subject: c.Subject, Email: c.Email})
			}
			if authors, err := r.Authors(ctx); err == nil {
				for _, a := range authors {
					ev.TotalCommits += a.Commits
				}
			}
			ev.Root, _ = r.Root(ctx)
			if files, err := r.TrackedFiles(ctx, 1<<30); err == nil {
				ev.Files = len(files)
				ev.Technologies = technologies(files)
			}
			out[i] = ev
		})
	}
	wg.Wait()
	ev := career.Evidence{Emails: emails}
	for _, r := range out {
		if r != nil {
			r.ID = fmt.Sprintf("g%d", len(ev.Repos)+1)
			ev.Repos = append(ev.Repos, *r)
		}
	}
	return ev
}

var (
	markdownNoise = regexp.MustCompile(`!?\[([^\]]*)\]\([^)]*\)|[*_` + "`" + `#>]`)
	readmeNames   = []string{"README.md", "README.rst", "README.txt", "README", "readme.md"}
)

// purpose is the README's first paragraph of prose, at most 400 characters.
func purpose(dir string) string {
	for _, name := range readmeNames {
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(f, 64<<10))
		f.Close()
		var para []string
		for _, line := range strings.Split(string(data), "\n") {
			t := strings.TrimSpace(line)
			switch {
			case t == "" && len(para) > 0:
				return trimText(strings.Join(para, " "), 400)
			case t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "[![") || strings.HasPrefix(t, "<") || strings.HasPrefix(t, "=") || strings.HasPrefix(t, "---"):
				continue
			}
			para = append(para, strings.TrimSpace(markdownNoise.ReplaceAllString(t, "$1")))
		}
		return trimText(strings.Join(para, " "), 400)
	}
	return ""
}

func trimText(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return strings.TrimSpace(string(r[:n]))
}

var (
	byExtension = map[string]string{".go": "Go", ".py": "Python", ".ts": "TypeScript", ".tsx": "TypeScript", ".js": "JavaScript",
		".jsx": "JavaScript", ".java": "Java", ".kt": "Kotlin", ".cs": "C#", ".rb": "Ruby", ".php": "PHP", ".rs": "Rust", ".swift": "Swift",
		".dart": "Dart", ".ps1": "PowerShell", ".sh": "Shell", ".tf": "Terraform", ".vue": "Vue", ".sql": "SQL", ".c": "C", ".cpp": "C++"}
	byFile = map[string]string{"Dockerfile": "Docker", "Chart.yaml": "Helm", "Jenkinsfile": "Jenkins", "cloudbuild.yaml": "Cloud Build",
		"angular.json": "Angular", "next.config.js": "Next.js", "next.config.ts": "Next.js", "pubspec.yaml": "Flutter", "kustomization.yaml": "Kubernetes"}
)

// technologies names the languages with at least three files and the tools
// marker files show, most files first.
func technologies(files []string) []string {
	n := map[string]int{}
	for _, f := range files {
		if t := byFile[filepath.Base(f)]; t != "" {
			n[t] += 3
		}
		if strings.HasPrefix(f, ".github/workflows/") {
			n["GitHub Actions"] += 3
		}
		if t := byExtension[strings.ToLower(filepath.Ext(f))]; t != "" {
			n[t]++
		}
	}
	var out []string
	for t, c := range n {
		if c >= 3 {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if n[out[i]] != n[out[j]] {
			return n[out[i]] > n[out[j]]
		}
		return out[i] < out[j]
	})
	return out[:min(len(out), 6)]
}

// --- questions ----------------------------------------------------------------

// savedFact is an answer kept by its question's key, since question IDs change
// when the map is rebuilt.
type savedFact struct {
	Key      string `json:"key"`
	Question string `json:"question"`
	Answer   string `json:"answer"`
}

func careerQuestions(ctx context.Context, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("career questions", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	again := flags.Bool("again", false, "")
	list := flags.Bool("list", false, "")
	if err := flags.Parse(args); err != nil || flags.NArg() > 0 {
		return fmt.Errorf("%w: career questions takes --again or --list", errUsage)
	}
	_, eng, err := careerGate(ctx)
	if err != nil {
		return err
	}
	m, _, err := loadMap(true)
	if err != nil {
		return err
	}
	qs := worded(eng.Questions(m))
	saved := map[string]savedFact{}
	var facts []savedFact
	if err := readState("facts.json", &facts); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, f := range facts {
		saved[f.Key] = f
	}
	if *list {
		for _, q := range qs {
			a := saved[q.key].Answer
			if a == "" {
				a = "(not answered; left out of drafts)"
			}
			fmt.Fprintf(stdout, "%s\n  %s\n\n", q.Text, a)
		}
		return nil
	}
	if !interactive() {
		return fmt.Errorf("%w: career questions asks in a terminal", errUsage)
	}
	fmt.Fprintln(stdout, "Answer in your own words; press Enter to skip. A skipped question leaves its claim out of the drafts, never guessed.")
	in := bufio.NewScanner(stdin)
	in.Buffer(make([]byte, 64<<10), 64<<10)
	asked := 0
	for i, q := range qs {
		if s, ok := saved[q.key]; ok && s.Answer != "" && !*again {
			continue
		}
		asked++
		fmt.Fprintf(stdout, "\n[%d/%d] %s\n> ", i+1, len(qs), q.Text)
		if !in.Scan() {
			break
		}
		answer := strings.TrimSpace(in.Text())
		if answer == "" {
			continue
		}
		saved[q.key] = savedFact{Key: q.key, Question: q.Text, Answer: answer}
		if err := saveFacts(saved); err != nil {
			return err
		}
	}
	if asked == 0 {
		fmt.Fprintln(stdout, "Every question is answered. Change answers with --again; see them with --list.")
	}
	fmt.Fprintln(stdout, "\nNext: urfluency career show to see what a draft would send, then urfluency career draft.")
	return nil
}

func saveFacts(saved map[string]savedFact) error {
	facts := make([]savedFact, 0, len(saved))
	for _, f := range saved {
		facts = append(facts, f)
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].Key < facts[j].Key })
	_, err := writeState("facts.json", facts)
	return err
}

type wordedQuestion struct {
	career.Question
	key string
}

// worded applies Vertex's wording to the engine's questions.
func worded(qs []career.Question) []wordedQuestion {
	wording := map[string]career.Question{}
	_ = readState("wording.json", &wording)
	out := make([]wordedQuestion, len(qs))
	for i, q := range qs {
		out[i] = wordedQuestion{q, questionKey(q)}
		if w, ok := wording[questionKey(q)]; ok && w.Text != "" {
			out[i].Text = w.Text
		}
	}
	return out
}

// careerFacts turns the saved answers into facts with the current questions'
// IDs.
func careerFacts(eng career.Engine, m career.Map) ([]career.Fact, error) {
	var facts []savedFact
	if err := readState("facts.json", &facts); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	saved := map[string]string{}
	for _, f := range facts {
		saved[f.Key] = f.Answer
	}
	var out []career.Fact
	for _, q := range eng.Questions(m) {
		if a := saved[questionKey(q)]; a != "" {
			out = append(out, career.Fact{ID: q.ID, Kind: q.Kind, RoleID: q.RoleID, FeatureID: q.FeatureID, Text: a})
		}
	}
	return out, nil
}

// --- show and draft -------------------------------------------------------------

// buildCareerPack builds, redacts, and validates the pack for a kind.
func buildCareerPack(eng career.Engine, kind string) (career.Pack, career.Map, error) {
	m, ev, err := loadMap(true)
	if err != nil {
		return career.Pack{}, m, err
	}
	facts, err := careerFacts(eng, m)
	if err != nil {
		return career.Pack{}, m, err
	}
	var target *career.Target
	var t career.Target
	if err := readState("target-"+kind+".json", &t); err == nil {
		target = &t
	} else if !errors.Is(err, fs.ErrNotExist) {
		return career.Pack{}, m, err
	}
	p := eng.BuildPack(kind, m, facts, target)
	career.RedactPack(&p, career.WithRepositories(career.ForPack(m.Names), ev))
	if err := career.ValidatePack(p); err != nil {
		return career.Pack{}, m, fmt.Errorf("not sending the pack: %w", err)
	}
	return p, m, nil
}

func careerShow(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("career show", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	resume := fs.Bool("resume", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return fmt.Errorf("%w: career show takes only --resume", errUsage)
	}
	_, eng, err := careerGate(ctx)
	if err != nil {
		return err
	}
	p, _, err := buildCareerPack(eng, kindOf(*resume))
	if err != nil {
		return err
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(p)
}

// slowClient is for calls that wait on Vertex AI. It waits as long as the API
// Gateway and Cloud Run do, so a draft the API writes and counts reaches the
// user.
var slowClient = &http.Client{Timeout: 150 * time.Second, CheckRedirect: sameOrigin}

func careerDraft(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("career draft", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	resume := fs.Bool("resume", false, "")
	yes := fs.Bool("yes", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return fmt.Errorf("%w: career draft takes --resume and --yes", errUsage)
	}
	acct, eng, err := careerGate(ctx)
	if err != nil {
		return err
	}
	switch {
	case acct.Plan != "pro":
		return errors.New("drafting is on Pro; everything before it is free: " + pricingURL)
	case !acct.Drafting:
		return errors.New("turn on \"Allow career drafts\" on urfluency.com/account/career first; it is off until you do")
	case acct.Left <= 0:
		return fmt.Errorf("you have used this week's %d drafts; the count resets on Monday (UTC)", acct.PerWeek)
	}
	kind := kindOf(*resume)
	p, _, err := buildCareerPack(eng, kind)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "This draft sends %s, %s in plain words, %s, and %s.\n",
		count(len(p.Roles), "role"), count(len(p.Features)+len(p.Side), "feature"), fmt.Sprintf("%d of your answers", len(p.Facts)), count(len(p.Skills), "skill"))
	fmt.Fprintln(stdout, "It does not contain code, file paths, repository names, URLs, email addresses, or internal names.")
	fmt.Fprintf(stdout, "urFluency deletes it once the draft reaches you. See every field with: urfluency career show%s\n", map[bool]string{true: " --resume"}[*resume])
	if !*yes {
		if !interactive() {
			return fmt.Errorf("%w: confirm with --yes when not running in a terminal", errUsage)
		}
		fmt.Fprintf(stdout, "Send it? It uses 1 of your %d drafts left this week. [y/N] ", acct.Left)
		in := bufio.NewScanner(stdin)
		if !in.Scan() || !strings.EqualFold(strings.TrimSpace(in.Text()), "y") && !strings.EqualFold(strings.TrimSpace(in.Text()), "yes") {
			fmt.Fprintln(stdout, "Nothing was sent.")
			return nil
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 150*time.Second)
	defer cancel()
	var d career.Draft
	status, code, err := signedJSONVia(ctx, slowClient, http.MethodPost, acct.creds.API+"/v1/career/drafts", acct.creds, p, &d)
	if err != nil {
		return fmt.Errorf("draft: %w", err)
	}
	if status/100 != 2 {
		return draftRefused(status, code)
	}
	name := fmt.Sprintf("drafts/%s-%s.json", kind, time.Now().UTC().Format("20060102-150405"))
	if _, err := writeState(name, d); err != nil {
		return err
	}
	if _, err := writeState("drafts/latest-"+kind+".json", d); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Drafted %d role %s.", len(d.Roles), plural(len(d.Roles), "entry", "entries"))
	if len(d.Dropped) > 0 {
		fmt.Fprintf(stdout, " %s left out because the evidence didn't support them.", count(len(d.Dropped), "sentence"))
	}
	fmt.Fprintf(stdout, "\nReview it: urfluency career review%s\n", map[bool]string{true: " --resume"}[*resume])
	return nil
}

func draftRefused(status int, code string) error {
	switch {
	case status == http.StatusUnauthorized:
		return loginRefused(code)
	case code == "pro_required":
		return errors.New("drafting is on Pro: " + pricingURL)
	case code == "drafting_off":
		return errors.New("turn on \"Allow career drafts\" on urfluency.com/account/career first")
	case code == "weekly_limit":
		return errors.New("you have used this week's drafts; the count resets on Monday (UTC)")
	case code == "draft_unusable":
		return errors.New("the draft came back from Vertex AI, but nothing in it passed the checks, so it counted toward your week. Check the pack with urfluency career show; answering more questions gives the draft more to cite")
	case code == "daily_limit":
		return errors.New("you have tried to draft too many times today; try again tomorrow (UTC). Failed tries don't use your week's drafts")
	case code == "paused":
		return errors.New("drafting is paused for now; try again later")
	case code == "pack_too_large":
		return errors.New("the pack is too large; leave out some repositories on the map")
	}
	return fmt.Errorf("draft: %s (%d)", code, status)
}
