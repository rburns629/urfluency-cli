package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/roburns/urfluency-cli/career"
	"github.com/roburns/urfluency-cli/internal/testutil"
)

// fakeCareerEngine stands in for the private engine.
type fakeCareerEngine struct{}

func (fakeCareerEngine) Analyze(p career.Profile, ev career.Evidence) career.Map {
	return career.Map{Format: career.Format, Roles: p.Positions}
}
func (fakeCareerEngine) Resolve(m career.Map, _ career.Evidence) career.Map { return m }
func (fakeCareerEngine) Questions(career.Map) []career.Question             { return nil }
func (fakeCareerEngine) LearnTarget(kind, _ string) career.Target           { return career.Target{Kind: kind} }
func (fakeCareerEngine) BuildPack(kind string, m career.Map, _ []career.Fact, _ *career.Target) career.Pack {
	return career.Pack{Format: career.Format, Kind: kind}
}
func (fakeCareerEngine) BuildAssist(career.Map, []career.Question) career.AssistRequest {
	return career.AssistRequest{Format: career.Format}
}

func withCareerEngine(t *testing.T) {
	career.Register(fakeCareerEngine{})
	t.Cleanup(func() { career.Register(nil) })
}

// loginForTest saves credentials for api with a key in the file.
func loginForTest(t *testing.T, api string) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	c := credentials{API: api, Token: "upload-token", Expires: time.Now().Add(time.Hour), KeyStore: "file", Key: base64.RawURLEncoding.EncodeToString(seed)}
	if err := c.save(); err != nil {
		t.Fatal(err)
	}
}

func TestCareerNeedsTheOfficialBuild(t *testing.T) {
	t.Setenv("URFLUENCY_CONFIG_DIR", t.TempDir())
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"career", "import", "export.zip"}, &out, &errOut); code != 1 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "official build") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func TestCareerNeedsSignIn(t *testing.T) {
	t.Setenv("URFLUENCY_CONFIG_DIR", t.TempDir())
	withCareerEngine(t)
	for _, step := range [][]string{{"import", "x.zip"}, {"target", "x.txt"}, {"map"}, {"questions", "--list"}, {"show"}, {"draft"}, {"review"}} {
		var out, errOut bytes.Buffer
		Run(context.Background(), append([]string{"career"}, step...), &out, &errOut)
		if !strings.Contains(errOut.String(), "signed-in account") {
			t.Errorf("career %s: stderr = %q, want the sign-in requirement", step[0], errOut.String())
		}
	}
}

func TestCareerGateAsksTheAPI(t *testing.T) {
	t.Setenv("URFLUENCY_CONFIG_DIR", t.TempDir())
	withCareerEngine(t)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/career" || r.Header.Get("X-Urfluency-Signature") == "" || r.Header.Get("Authorization") != "Bearer upload-token" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(apiError{Error: "unauthorized"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"plan": "pro", "drafting": false, "drafts_left": 3, "drafts_per_week": 3})
	}))
	defer api.Close()
	loginForTest(t, api.URL)
	a, eng, err := careerGate(context.Background())
	if err != nil || eng == nil {
		t.Fatalf("gate: %v", err)
	}
	if a.Plan != "pro" || a.Drafting || a.vertex() || a.Left != 3 {
		t.Errorf("account = %+v", a)
	}
	// Drafting refuses until the account turns it on.
	var out bytes.Buffer
	if err := careerDraft(context.Background(), []string{"--yes"}, &out); err == nil || !strings.Contains(err.Error(), "Allow career drafts") {
		t.Errorf("draft with drafting off: %v", err)
	}
}

func TestCareerStateIsOwnerOnly(t *testing.T) {
	t.Setenv("URFLUENCY_CONFIG_DIR", t.TempDir())
	path, err := writeState("map.json", career.Map{Format: career.Format})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", info.Mode().Perm())
	}
	dir, _ := os.Stat(filepath.Dir(path))
	if dir.Mode().Perm() != 0o700 {
		t.Errorf("folder mode %v", dir.Mode().Perm())
	}
}

func TestServePageRefusesOtherCallers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	links := make(chan string, 1)
	openBrowser = func(link string) error { links <- link; return nil }
	t.Cleanup(func() { openBrowser = func(string) error { return nil } })
	acted := 0
	go servePage(ctx, io.Discard, "map.html", func() any { return map[string]int{"acted": acted} },
		func(action string, _ json.RawMessage) (bool, error) { acted++; return false, nil }, false)
	link := <-links
	get := func(url string, header map[string]string, method string) int {
		req, _ := http.NewRequest(method, url, strings.NewReader("{}"))
		for k, v := range header {
			if k == "Host" {
				req.Host = v
				continue
			}
			req.Header.Set(k, v)
		}
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	token := strings.Split(strings.TrimPrefix(link, "http://"), "/")[1]
	if got := get(link, nil, http.MethodGet); got != http.StatusOK {
		t.Errorf("page: %d", got)
	}
	if got := get(strings.Replace(link, token, "wrong-token-wrong-token-wrong", 1), nil, http.MethodGet); got != http.StatusNotFound {
		t.Errorf("wrong token: %d", got)
	}
	if got := get(link+"act/decide", nil, http.MethodPost); got != http.StatusForbidden {
		t.Errorf("change without the header: %d", got)
	}
	if got := get(link, map[string]string{"Host": "rebound.example:80"}, http.MethodGet); got != http.StatusNotFound {
		t.Errorf("another Host, as after DNS rebinding: %d", got)
	}
	if got := get(link+"act/decide", map[string]string{"X-Urfluency-Page": token}, http.MethodPost); got != http.StatusOK || acted != 1 {
		t.Errorf("change with the header: %d, acted %d", got, acted)
	}
}

func TestRenderResume(t *testing.T) {
	d := career.Draft{Kind: career.Resume, Summary: []career.Sentence{{Text: "Engineer building platforms."}},
		Competencies: []string{"Platform Engineering"}, Skills: []string{"Go"}, Implied: []string{"SQL", "Docker"},
		Roles: []career.RoleDraft{{RoleID: "r1", Bullets: []career.Bullet{
			{Sentence: career.Sentence{Text: "Built <the> API."}, Rank: 1, Keep: true},
			{Sentence: career.Sentence{Text: "Wrote docs."}, Rank: 2}}}}}
	roles := map[string]career.Position{"r1": {ID: "r1", Title: "Engineer", Official: "Technical Analyst", Note: "Software Engineer", Company: "Example Co", Start: "2021-03"}}
	md, _, err := renderResume(d, roles, "Jane Doe", resumeChoice{Format: "md", OnePage: true, Shown: []string{"r1:1"}, Drop: []string{"Docker"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# Jane Doe", "Go | SQL", "**Technical Analyst (Software Engineer)** · Example Co · Mar 2021 – Present", "- Built <the> API."} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q:\n%s", want, md)
		}
	}
	if strings.Contains(md, "Wrote docs") || strings.Contains(md, "Docker") {
		t.Errorf("cut bullet or dropped skill kept:\n%s", md)
	}
	page, _, _ := renderResume(d, roles, "Jane Doe", resumeChoice{Format: "html"})
	if !strings.Contains(page, "Built &lt;the&gt; API.") || !strings.Contains(page, "Wrote docs") {
		t.Errorf("html not escaped or two-page bullets missing:\n%s", page)
	}
}

func TestCollectEvidence(t *testing.T) {
	root := t.TempDir()
	r := &testutil.Repo{T: t, Dir: filepath.Join(root, "work", "api")}
	if err := os.MkdirAll(r.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	r.Git("", "", "init", "-q", "-b", "main")
	r.Commit("me@example.com", "2024-01-02T10:00:00Z", map[string]string{"README.md": "# API\n\nThe accounts API for the platform.\n\nMore.", "a.go": "package a\n", "b.go": "package b\n", "c.go": "package c\n", "main.tf": ""})
	r.Commit("other@example.com", "2024-01-03T10:00:00Z", map[string]string{"d.go": "package d\n"})
	ev := collectEvidence(context.Background(), root, []string{r.Dir}, []string{"me@example.com"})
	if len(ev.Repos) != 1 {
		t.Fatalf("repos = %+v", ev.Repos)
	}
	got := ev.Repos[0]
	if got.ID != "g1" || got.Folder != "work/api" || len(got.Commits) != 1 || got.TotalCommits != 2 || got.Root == "" || got.Files != 6 {
		t.Errorf("evidence = %+v", got)
	}
	if got.Purpose != "The accounts API for the platform." || len(got.Technologies) == 0 || got.Technologies[0] != "Go" {
		t.Errorf("purpose %q, technologies %v", got.Purpose, got.Technologies)
	}
}

// An answer is kept across rebuilt maps whose figures changed.
func TestQuestionKeyIgnoresFigures(t *testing.T) {
	before := career.Question{ID: "q1", Kind: career.FactOwnership, RoleID: "r1", Text: "As Engineer: you made 34% of the commits behind the work on api."}
	after := before
	after.ID, after.Text = "q4", "As Engineer: you made 31% of the commits behind the work on api."
	if questionKey(before) != questionKey(after) {
		t.Errorf("keys differ: %q, %q", questionKey(before), questionKey(after))
	}
	other := before
	other.Text = "As Engineer: you made 34% of the commits behind the work on queue."
	if questionKey(before) == questionKey(other) {
		t.Error("questions about different features share a key")
	}
}
