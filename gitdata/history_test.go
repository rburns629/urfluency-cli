package gitdata_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/roburns/urfluency-cli/gitdata"
	"github.com/roburns/urfluency-cli/internal/testutil"
)

func TestFixHistory(t *testing.T) {
	r := testutil.NewRepo(t)
	r.Commit("me@example.com", "2025-01-01T00:00:00Z", map[string]string{"a.go": "one\ntwo\nthree\n", "notes.md": "x\n"})
	if err := os.WriteFile(filepath.Join(r.Dir, "a.go"), []byte("one\nTWO\nthree\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r.Git("other@example.com", "2025-01-10T00:00:00Z", "commit", "-qam", "fix: correct the second line")
	r.Git("me@example.com", "2025-01-12T00:00:00Z", "mv", "a.go", "b.go")
	r.Git("me@example.com", "2025-01-12T00:00:00Z", "commit", "-qm", "Rename a to b")
	repo := gitdata.Repo{Dir: r.Dir}
	ctx := context.Background()

	commits, err := repo.Commits(ctx, []string{"me@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	byDay := map[string]string{}
	for hash, c := range commits {
		byDay[c.Time.UTC().Format("2006-01-02")] = hash
	}
	first, rename := byDay["2025-01-01"], byDay["2025-01-12"]
	if first == "" || rename == "" {
		t.Fatalf("commits = %+v", commits)
	}

	added, err := repo.AddedLines(ctx, []string{"me@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(added[first], map[string]int{"a.go": 3, "notes.md": 1}) || added[rename]["b.go"] != 0 {
		t.Errorf("added = %v; want 3 lines in a.go first and none for the rename", added)
	}

	fixes, err := repo.FixCommits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(fixes) != 1 || fixes[0].Time.UTC().Format("2006-01-02") != "2025-01-10" {
		t.Fatalf("fixes = %+v, want only the fix: commit", fixes)
	}
	fixed, err := repo.FixedLines(ctx, fixes[0].Hash, func(p string) bool { return p == "a.go" })
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fixed, map[string]int{first: 1}) {
		t.Errorf("fixed lines = %v, want the rewritten line traced to %s", fixed, first)
	}
}

func TestTouchedPathsFollowsRenames(t *testing.T) {
	r := testutil.NewRepo(t)
	r.Commit("me@example.com", "", map[string]string{"old/a.go": "package a\n"})
	r.Commit("other@example.com", "", map[string]string{"theirs.go": "package b\n"})
	r.Git("other@example.com", "", "mv", "old/a.go", "a.go")
	r.Git("other@example.com", "", "commit", "-qm", "Move a")
	repo := gitdata.Repo{Dir: r.Dir}

	touched, err := repo.TouchedPaths(context.Background(), []string{"ME@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !touched["a.go"] || touched["theirs.go"] {
		t.Errorf("touched = %v, want a.go (renamed by someone else) and not theirs.go", touched)
	}
	none, err := repo.TouchedPaths(context.Background(), []string{"nobody@example.com"})
	if err != nil || len(none) != 0 {
		t.Errorf("touched for an author with no commits = %v, %v", none, err)
	}
}

func TestAuthorMatchingIsLiteralAndExact(t *testing.T) {
	r := testutil.NewRepo(t)
	noreply := "16638916+someone@users.noreply.github.com"
	r.Commit(noreply, "", map[string]string{"mine.go": "package a\n"})
	r.Commit("nome@example.com", "", map[string]string{"theirs.go": "package a\n"})
	repo := gitdata.Repo{Dir: r.Dir}
	ctx := context.Background()

	commits, err := repo.Commits(ctx, []string{noreply})
	if err != nil || len(commits) != 1 {
		t.Errorf("a noreply address with + matched %d commits (%v), want 1", len(commits), err)
	}
	touched, err := repo.TouchedPaths(ctx, []string{"ME@example.com"})
	if err != nil || len(touched) != 0 {
		t.Errorf("me@example.com must not match nome@example.com: %v %v", touched, err)
	}
	added, err := repo.AddedLines(ctx, []string{noreply})
	if err != nil || len(added) != 1 {
		t.Errorf("added lines for the noreply address: %v %v", added, err)
	}
}

// A shallow clone's oldest commit has no parent, so it would count every file as
// added; AddedLines leaves it out.
func TestAddedLinesSkipsShallowBoundary(t *testing.T) {
	r := testutil.NewRepo(t)
	r.Commit("me@example.com", "2025-01-01T00:00:00Z", map[string]string{"old.go": "a\nb\nc\n"})
	r.Commit("me@example.com", "2025-02-01T00:00:00Z", map[string]string{"mid.go": "a\n"})
	r.Commit("me@example.com", "2025-03-01T00:00:00Z", map[string]string{"new.go": "a\nb\n"})
	clone := filepath.Join(t.TempDir(), "clone")
	r.Git("me@example.com", "", "clone", "-q", "--depth=2", "file://"+r.Dir, clone)
	ctx := context.Background()

	full, err := gitdata.Repo{Dir: r.Dir}.Shallow(ctx)
	if err != nil || full {
		t.Fatalf("Shallow(full clone) = %v, %v", full, err)
	}
	repo := gitdata.Repo{Dir: clone}
	if shallow, err := repo.Shallow(ctx); err != nil || !shallow {
		t.Fatalf("Shallow(depth 2) = %v, %v", shallow, err)
	}
	added, err := repo.AddedLines(ctx, gitdata.Everyone)
	if err != nil {
		t.Fatal(err)
	}
	var got []map[string]int
	for _, perPath := range added {
		got = append(got, perPath)
	}
	if want := []map[string]int{{"new.go": 2}}; !reflect.DeepEqual(got, want) {
		t.Errorf("added = %v, want only the newest commit's %v", got, want)
	}
}

// Paths git would quote must still match the paths ls-tree lists: café.go is
// quoted by default, and a name with a quote is quoted even with quotePath off.
func TestHistoryPathsAreLiteral(t *testing.T) {
	r := testutil.NewRepo(t)
	r.Commit("me@example.com", "", map[string]string{"café.go": "package a\n", `a"b.go`: "package a\n"})
	r.Git("me@example.com", "", "mv", "café.go", "naïve.go")
	r.Git("me@example.com", "", "commit", "-qm", "Rename")
	ctx := context.Background()
	repo := gitdata.Repo{Dir: r.Dir}
	touched, err := repo.TouchedPaths(ctx, []string{"me@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !touched["naïve.go"] || !touched[`a"b.go`] {
		t.Errorf("touched = %v, want naïve.go (renamed from café.go) and a\"b.go", touched)
	}
	added, err := repo.AddedLines(ctx, []string{"me@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, perPath := range added {
		for p := range perPath {
			found[p] = true
		}
	}
	if !found["café.go"] || !found[`a"b.go`] {
		t.Errorf("added paths = %v, want café.go and a\"b.go", found)
	}
}

// Removing a line that starts with "-- ", such as a Lua or SQL comment, shows
// as "--- …" inside a hunk; the file's later hunks must still be traced.
func TestFixedLinesAfterARemovedDashComment(t *testing.T) {
	r := testutil.NewRepo(t)
	lines := []string{"local a = 1", "-- note", "local b = 2", "", "", "", "", "", "", "local c = 3", "return a"}
	r.Commit("me@example.com", "", map[string]string{"x.lua": strings.Join(lines, "\n") + "\n"})
	fixed := append(append([]string{}, lines[:1]...), lines[2:]...)
	fixed[8] = "local c = 4"
	if err := os.WriteFile(filepath.Join(r.Dir, "x.lua"), []byte(strings.Join(fixed, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r.Git("me@example.com", "", "commit", "-qam", "fix: c")
	repo := gitdata.Repo{Dir: r.Dir}
	head, err := repo.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, err := repo.FixedLines(context.Background(), head, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, n := range got {
		total += n
	}
	if total != 2 {
		t.Errorf("traced %d lines, want the removed comment and the changed line", total)
	}
	root, err := repo.FixedLines(context.Background(), head+"^", func(string) bool { return true })
	if !errors.Is(err, gitdata.ErrNoParent) {
		t.Errorf("root commit: %v, %v; want ErrNoParent", root, err)
	}
}
