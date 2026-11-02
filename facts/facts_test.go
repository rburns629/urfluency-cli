package facts_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rburns629/urfluency-cli/analysis"
	"github.com/rburns629/urfluency-cli/facts"
	"github.com/rburns629/urfluency-cli/gitdata"
	"github.com/rburns629/urfluency-cli/internal/report"
	"github.com/rburns629/urfluency-cli/internal/sessions"
	"github.com/rburns629/urfluency-cli/internal/testutil"

	_ "github.com/rburns629/urfluency-cli/analyzers/all" // every analyzer
)

var since = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

// scan builds two repositories with findings, idioms, tests, CI, and an
// AI-marked commit, and merges them as a scan of a projects folder does.
func scan(t *testing.T) analysis.Result {
	t.Helper()
	ctx := context.Background()
	a := testutil.NewRepo(t)
	a.Commit("ana@example.com", "2026-03-01T00:00:00Z", map[string]string{
		"go.mod": "module example.com/a\n\ngo 1.26\n",
		"svc/svc.go": "package svc\n\nimport (\n\t\"context\"\n\t\"fmt\"\n\t\"net/http\"\n)\n\n// Get fetches url.\nfunc Get(ctx context.Context, url string) error {\n" +
			"\treq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)\n\tif err != nil {\n\t\treturn fmt.Errorf(\"get: %w\", err)\n\t}\n" +
			"\tresp, err := http.DefaultClient.Do(req)\n\tif err != nil {\n\t\treturn fmt.Errorf(\"get: %w\", err)\n\t}\n\tdefer resp.Body.Close()\n\treturn nil\n}\n",
		"svc/svc_test.go":          "package svc\n\nimport \"testing\"\n\nfunc TestGet(t *testing.T) {}\n",
		".github/workflows/ci.yml": "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: go vet ./...\n      - run: go test ./...\n",
	})
	run := "package svc\n\nimport \"os/exec\"\n\n// Run runs a shell command.\nfunc Run(cmd string) error {\n\treturn exec.Command(\"sh\", \"-c\", cmd).Run()\n}\n"
	if err := os.WriteFile(filepath.Join(a.Dir, "svc", "run.go"), []byte(run), 0o644); err != nil {
		t.Fatal(err)
	}
	a.Git("ana@example.com", "2026-04-01T00:00:00Z", "add", "-A")
	a.Git("ana@example.com", "2026-04-01T00:00:00Z", "commit", "-q", "-m", "Add Run\n\nCo-Authored-By: Claude <noreply@anthropic.com>")
	b := testutil.NewRepo(t)
	b.Commit("ana@example.com", "2026-05-01T00:00:00Z", map[string]string{
		"app.py": "import subprocess\n\n\ndef run(cmd):\n    return eval(cmd)\n\n\ndef call(args):\n    subprocess.run(args, shell=True)\n",
	})
	var parts []analysis.Result
	for _, dir := range []string{a.Dir, b.Dir} {
		res, err := analysis.Scan(ctx, gitdata.Repo{Dir: dir}, analysis.Options{Emails: gitdata.Everyone, Since: since})
		if err != nil {
			t.Fatal(err)
		}
		parts = append(parts, res)
	}
	return analysis.Merge([]string{"work/secret-project", "side/other-project"}, parts)
}

// build makes the parts of a report an upload carries, as the CLI does.
func build(git analysis.Result, grades *sessions.Grades) []byte {
	r := report.Build(git, since, false)
	r.Combined = report.BuildCombined(git, analysis.Result{})
	if grades != nil {
		r.Prompting = report.BuildPrompting(*grades)
	}
	if git.OwnedLines > 0 {
		r.AI = report.BuildAI(git, grades != nil)
		r.AIEngineering = report.BuildAIEngineering(r)
		r.Practices = report.BuildPractices(git)
	}
	report.Summarize(&r)
	out, _ := json.Marshal(struct {
		Summary  any `json:"summary"`
		Combined any `json:"combined"`
	}{r.Summary, r.Combined})
	return out
}

// Scoring the facts, after a trip through JSON, gives the same summary and
// combined result as scoring the scan itself.
func TestFactsScoreLikeTheScan(t *testing.T) {
	res := scan(t)
	if len(res.Languages) == 0 || res.Findings == 0 {
		t.Fatalf("the fixture found nothing to score: %+v", res)
	}
	grades := &sessions.Grades{Sessions: 3, Tasks: map[string]int{"bug": 2}, Rules: map[string]sessions.Tally{"prompt.context": {Applicable: 2, Missed: 1}},
		Edits: 4, Reviewed: 1, EditTasks: 2, GateTasks: map[string]int{"test": 1}, Style: map[string]int{"context": 1}}
	f := facts.New(res, analysis.Result{}, grades)
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var back facts.Facts
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.Git == nil || back.Folders != nil || back.Sessions == nil {
		t.Fatalf("facts parts: git %v, folders %v, sessions %v", back.Git != nil, back.Folders != nil, back.Sessions != nil)
	}
	g := back.Sessions.Grades()
	want, got := build(res, grades), build(back.Git.Result(), &g)
	if !bytes.Equal(want, got) {
		t.Errorf("scored from facts:\n%s\nscored from the scan:\n%s", got, want)
	}
}

// Facts carry no repository label, path, or commit hash.
func TestFactsLeaveOutIdentifyingFields(t *testing.T) {
	res := scan(t)
	data, err := json.Marshal(facts.New(res, analysis.Result{}, nil))
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, leak := range []string{"secret-project", "other-project", "svc/", "app.py", "ci.yml", "example.com"} {
		if strings.Contains(s, leak) {
			t.Errorf("facts contain %q: %s", leak, s)
		}
	}
	if res.Head != "" && strings.Contains(s, res.Head) {
		t.Errorf("facts contain the commit hash")
	}
	if !strings.Contains(s, `"findings_by_rule"`) || !strings.Contains(s, `"projects"`) {
		t.Errorf("facts lack per-rule findings or projects: %s", s)
	}
}
