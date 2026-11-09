package cli

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/roburns/urfluency-cli/career"
)

// The map and review pages are served by the CLI on 127.0.0.1, so the
// evidence never leaves the machine. Each run picks a random port and a
// random token; every request must carry the token in its path, and every
// change also in a header, which other sites' pages cannot send, and the
// Host must be the listener's own address, against DNS rebinding.

//go:embed careerpages/*.html
var careerPages embed.FS

// pageAction changes the state; done ends the page.
type pageAction func(action string, body json.RawMessage) (done bool, err error)

func servePage(ctx context.Context, stdout io.Writer, page string, state func() any, act pageAction, noBrowser bool) error {
	body, err := careerPages.ReadFile("careerpages/" + page)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	token := randomString(24)
	host := ln.Addr().String()
	prefix := "/" + token + "/"
	var mu sync.Mutex
	done := make(chan struct{})
	var once sync.Once
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Host != host || !strings.HasPrefix(r.URL.Path, prefix) || subtle.ConstantTimeCompare([]byte(r.URL.Path[1:len(prefix)-1]), []byte(token)) != 1 {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, prefix)
		switch {
		case r.Method == http.MethodGet && rest == "":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
			w.Write(body)
		case r.Method == http.MethodGet && rest == "state":
			mu.Lock()
			defer mu.Unlock()
			writePageJSON(w, http.StatusOK, state())
		case r.Method == http.MethodPost && strings.HasPrefix(rest, "act/"):
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Urfluency-Page")), []byte(token)) != 1 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			finished, err := act(strings.TrimPrefix(rest, "act/"), raw)
			if err != nil {
				writePageJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writePageJSON(w, http.StatusOK, state())
			if finished {
				once.Do(func() { close(done) })
			}
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln)
	link := "http://" + host + prefix
	fmt.Fprintf(stdout, "Open %s\nIt is served by this CLI on your computer only. Press Ctrl-C to stop.\n", link)
	if !noBrowser {
		_ = openBrowser(link)
	}
	select {
	case <-done:
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}

func writePageJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// --- map page ---------------------------------------------------------------------

// mapRepo is what the map page shows of a repository. It stays local.
type mapRepo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Folder  string `json:"folder"`
	Commits int    `json:"commits"`
	Total   int    `json:"total"`
}

func serveMap(ctx context.Context, stdout io.Writer, eng career.Engine, profile career.Profile, ev career.Evidence, m career.Map, noBrowser bool) error {
	repos := make([]mapRepo, len(ev.Repos))
	for i, r := range ev.Repos {
		repos[i] = mapRepo{r.ID, r.Name, r.Folder, len(r.Commits), r.TotalCommits}
	}
	state := func() any { return map[string]any{"map": m, "repos": repos, "pending": m.Pending()} }
	act := func(action string, raw json.RawMessage) (bool, error) {
		var b struct {
			ID       string `json:"id"`
			Choice   int    `json:"choice"`
			Official string `json:"official"`
			Note     string `json:"note"`
			Generic  string `json:"generic"`
			Public   bool   `json:"public"`
		}
		if err := json.Unmarshal(raw, &b); err != nil {
			return false, err
		}
		switch action {
		case "decide":
			i := slices.IndexFunc(m.Decisions, func(d career.Decision) bool { return d.ID == b.ID })
			if i < 0 || b.Choice < 0 || b.Choice >= len(m.Decisions[i].Options) {
				return false, errors.New("unknown decision or option")
			}
			m.Decisions[i].Choice = b.Choice
			m.Approved = false
			m = eng.Resolve(m, ev)
		case "title":
			i := slices.IndexFunc(m.Roles, func(r career.Position) bool { return r.ID == b.ID })
			if i < 0 || len(b.Official) > 120 || len(b.Note) > 120 {
				return false, errors.New("unknown role or title too long")
			}
			m.Roles[i].Official, m.Roles[i].Note = strings.TrimSpace(b.Official), strings.TrimSpace(b.Note)
			for j := range profile.Positions {
				if profile.Positions[j].ID == b.ID {
					profile.Positions[j].Official, profile.Positions[j].Note = m.Roles[i].Official, m.Roles[i].Note
				}
			}
			if _, err := writeState("profile.json", profile); err != nil {
				return false, err
			}
		case "name":
			i := slices.IndexFunc(m.Names, func(n career.Name) bool { return n.Token == b.ID })
			if i < 0 || len(b.Generic) > 60 {
				return false, errors.New("unknown name or description too long")
			}
			m.Names[i].Generic, m.Names[i].Public, m.Names[i].Confirmed = strings.TrimSpace(b.Generic), b.Public, true
		case "approve":
			if n := m.Pending(); n > 0 {
				return false, fmt.Errorf("%s still open", count(n, "decision"))
			}
			m.Approved = true
		default:
			return false, errors.New("unknown action")
		}
		if _, err := writeState("map.json", m); err != nil {
			return false, err
		}
		if action == "approve" {
			fmt.Fprintln(stdout, "Map approved. Next: urfluency career questions")
		}
		return action == "approve", nil
	}
	return servePage(ctx, stdout, "map.html", state, act, noBrowser)
}

// --- review page ----------------------------------------------------------------

// citation is what a sentence's citation shows: a feature from the user's
// commits, or one of their answers. It stays local.
type citation struct {
	Kind   string `json:"kind"` // "git" or "you"
	Label  string `json:"label"`
	Detail string `json:"detail"`
}

func careerReview(ctx context.Context, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("career review", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	resume := flags.Bool("resume", false, "")
	noBrowser := flags.Bool("no-browser", false, "")
	if err := flags.Parse(args); err != nil || flags.NArg() > 0 {
		return fmt.Errorf("%w: career review takes --resume and --no-browser", errUsage)
	}
	_, eng, err := careerGate(ctx)
	if err != nil {
		return err
	}
	kind := kindOf(*resume)
	var d career.Draft
	if err := readState("drafts/latest-"+kind+".json", &d); err != nil {
		return fmt.Errorf("no %s draft yet; run urfluency career draft%s", kind, map[bool]string{true: " --resume"}[*resume])
	}
	m, ev, err := loadMap(false)
	if err != nil {
		return err
	}
	profile, _ := loadProfile()
	facts, err := careerFacts(eng, m)
	if err != nil {
		return err
	}
	cites := map[string]citation{}
	repoName := map[string]string{}
	for _, r := range ev.Repos {
		repoName[r.ID] = r.Name
	}
	for _, f := range m.Features {
		label := repoName[f.RepoID]
		cites[f.ID] = citation{"git", label, fmt.Sprintf("%s · %d commits, %s to %s · %d%% of the repository's commits are yours",
			describeFeature(f), f.Commits, f.Start.Format("Jan 2006"), f.End.Format("Jan 2006"), f.Share)}
	}
	questions := map[string]string{}
	for _, q := range worded(eng.Questions(m)) {
		questions[q.ID] = q.Text
	}
	for _, f := range facts {
		cites[f.ID] = citation{"you", "Your answer", fmt.Sprintf("%s — %q", questions[f.ID], f.Text)}
	}
	roles := map[string]career.Position{}
	for _, r := range m.Roles {
		roles[r.ID] = r
	}
	state := func() any {
		return map[string]any{"draft": d, "cites": cites, "roles": m.Roles, "name": profile.Name}
	}
	act := func(action string, raw json.RawMessage) (bool, error) {
		if action != "save" || kind != career.Resume {
			return false, errors.New("unknown action")
		}
		var b resumeChoice
		if err := json.Unmarshal(raw, &b); err != nil {
			return false, err
		}
		text, ext, err := renderResume(d, roles, profile.Name, b)
		if err != nil {
			return false, err
		}
		pages := map[bool]string{true: "1page", false: "2page"}[b.OnePage]
		path, err := writeStateBytes("drafts/resume-"+pages+"."+ext, []byte(text))
		if err != nil {
			return false, err
		}
		fmt.Fprintln(stdout, "Saved", path)
		return false, nil
	}
	return servePage(ctx, stdout, "review.html", state, act, *noBrowser)
}

func describeFeature(f career.Feature) string {
	if f.Summary != "" {
		return f.Summary
	}
	t, _, _ := strings.Cut(f.Title, " (")
	return t
}

// resumeChoice is what the review page sends to save a resume.
type resumeChoice struct {
	Format  string   `json:"format"` // "md" or "html"
	OnePage bool     `json:"one_page"`
	Shown   []string `json:"shown"` // "role:rank" of each bullet kept
	Drop    []string `json:"drop"`  // implied skills dropped
}

// renderResume writes the resume as Markdown, or as HTML to print to PDF.
func renderResume(d career.Draft, roles map[string]career.Position, name string, c resumeChoice) (string, string, error) {
	if c.Format != "md" && c.Format != "html" {
		return "", "", errors.New("format must be md or html")
	}
	shown := map[string]bool{}
	for _, s := range c.Shown {
		shown[s] = true
	}
	var summary []string
	for _, s := range d.Summary {
		summary = append(summary, s.Text)
	}
	skills := slices.Clone(d.Skills)
	for _, s := range d.Implied {
		if !slices.Contains(c.Drop, s) {
			skills = append(skills, s)
		}
	}
	var b strings.Builder
	esc := func(s string) string { return s }
	if c.Format == "html" {
		esc = html.EscapeString
		b.WriteString(`<!doctype html><meta charset="utf-8"><title>Resume</title><style>body{font:11pt Arial,Helvetica,sans-serif;max-width:7.5in;margin:.5in auto;color:#111}h1{font-size:18pt;margin:0;text-align:center}h2{font-size:10.5pt;text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid #111;margin:14px 0 6px}.r{display:flex;justify-content:space-between;font-weight:bold}.o{font-style:italic}ul{margin:4px 0 10px;padding-left:18px}p{margin:0}</style>`)
		fmt.Fprintf(&b, "<h1>%s</h1>", esc(name))
	} else {
		fmt.Fprintf(&b, "# %s\n", name)
	}
	section := func(title, body string) {
		if body == "" {
			return
		}
		if c.Format == "html" {
			fmt.Fprintf(&b, "<h2>%s</h2><p>%s</p>", title, esc(body))
		} else {
			fmt.Fprintf(&b, "\n## %s\n\n%s\n", title, body)
		}
	}
	section("Professional Summary", strings.Join(summary, " "))
	section("Core Competencies", strings.Join(d.Competencies, " | "))
	section("Technical Skills", strings.Join(skills, " | "))
	if c.Format == "html" {
		b.WriteString("<h2>Professional Experience</h2>")
	} else {
		b.WriteString("\n## Professional Experience\n")
	}
	for _, r := range d.Roles {
		pos := roles[r.RoleID]
		title := pos.Title
		if pos.Official != "" {
			title = pos.Official
		}
		if pos.Note != "" {
			title += " (" + pos.Note + ")"
		}
		dates := monthName(pos.Start) + " – " + map[bool]string{true: "Present", false: monthName(pos.End)}[pos.End == ""]
		if c.Format == "html" {
			fmt.Fprintf(&b, `<div class="r"><span>%s</span><span>%s</span></div><div class="o">%s</div><ul>`, esc(title), esc(dates), esc(pos.Company))
		} else {
			fmt.Fprintf(&b, "\n**%s** · %s · %s\n\n", title, pos.Company, dates)
		}
		for _, bl := range r.Bullets {
			if c.OnePage && !shown[fmt.Sprintf("%s:%d", r.RoleID, bl.Rank)] {
				continue
			}
			if c.Format == "html" {
				fmt.Fprintf(&b, "<li>%s</li>", esc(bl.Text))
			} else {
				fmt.Fprintf(&b, "- %s\n", bl.Text)
			}
		}
		if c.Format == "html" {
			b.WriteString("</ul>")
		}
	}
	return b.String(), c.Format, nil
}

func monthName(m string) string {
	t, err := time.Parse("2006-01", m)
	if err != nil {
		return m
	}
	return t.Format("Jan 2006")
}
