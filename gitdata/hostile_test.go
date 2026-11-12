package gitdata_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/roburns/urfluency-cli/gitdata"
	"github.com/roburns/urfluency-cli/internal/testutil"
)

// A scanned folder's own .git/config is untrusted: it can name programs for
// Git to run. This builds a repository whose config points every such setting
// at a script that writes a marker file, checks that plain git does run it,
// and then that nothing this package does runs it.
func TestRepositoryConfigRunsNoProgram(t *testing.T) {
	ctx := context.Background()
	const me = "me@example.com"
	tr := testutil.NewRepo(t)
	marker := filepath.Join(t.TempDir(), "marker")
	script := filepath.Join(tr.Dir, "run.sh")
	body := fmt.Sprintf("#!/bin/sh\necho ran >> %q\nexit 1\n", marker)
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	tr.Commit(me, "2026-01-01T00:00:00Z", map[string]string{"a.go": "package a\n\nfunc A() int { return 1 }\n", ".gitattributes": "*.go diff=evil\n"})
	tr.Commit(me, "2026-01-02T00:00:00Z", map[string]string{"a.go": "package a\n\nfunc A() int { return 2 }\n"})

	// A commit with a signature header, so Git has a signature to check.
	tree := strings.TrimSpace(gitOut(t, tr.Dir, "", "rev-parse", "HEAD^{tree}"))
	parent := strings.TrimSpace(gitOut(t, tr.Dir, "", "rev-parse", "HEAD"))
	commit := "tree " + tree + "\nparent " + parent + "\n" +
		"author Test <" + me + "> 1767400000 +0000\ncommitter Test <" + me + "> 1767400000 +0000\n" +
		"gpgsig -----BEGIN PGP SIGNATURE-----\n \n iQEzBAABCAAdFiEE\n -----END PGP SIGNATURE-----\n\nfix: signed\n"
	signed := strings.TrimSpace(gitOut(t, tr.Dir, commit, "hash-object", "-t", "commit", "-w", "--stdin"))
	tr.Git(me, "", "update-ref", "HEAD", signed)

	for key, value := range map[string]string{
		"log.showSignature":         "true",
		"gpg.program":               "./run.sh",
		"gpg.ssh.program":           "./run.sh",
		"gpg.x509.program":          "./run.sh",
		"core.fsmonitor":            "./run.sh",
		"core.pager":                "./run.sh",
		"core.sshCommand":           "./run.sh",
		"core.alternateRefsCommand": "./run.sh",
		"diff.external":             "./run.sh",
		"diff.evil.command":         "./run.sh",
		"diff.evil.textconv":        "./run.sh",
	} {
		tr.Git(me, "", "config", key, value)
	}
	hooks := filepath.Join(tr.Dir, "hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"post-index-change", "reference-transaction"} {
		if err := os.WriteFile(filepath.Join(hooks, h), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	tr.Git(me, "", "config", "core.hooksPath", hooks)

	// The test proves nothing unless the config works: plain git must run it.
	plain := exec.Command("git", "-C", tr.Dir, "log", "--format=%an")
	plain.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	_ = plain.Run()
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("plain git log did not run the configured program, so this test would pass for nothing")
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}

	repo := gitdata.Repo{Dir: tr.Dir}
	emails := []string{me}
	head, err := repo.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Errors are not this test's subject; each call only has to run git.
	repo.TopLevel(ctx)
	repo.Ignored(ctx)
	repo.Vendored(ctx, []string{"a.go"})
	repo.ConfiguredName(ctx)
	repo.ConfiguredEmail(ctx)
	repo.Authors(ctx)
	repo.TrackedFiles(ctx, 1<<20)
	repo.Shallow(ctx)
	repo.Show(ctx, head, "a.go")
	repo.OwnedLines(ctx, head, "a.go", emails, time.Time{})
	commits, _ := repo.Commits(ctx, emails)
	repo.AuthoredCommits(ctx, emails)
	repo.Root(ctx)
	repo.AddedLines(ctx, emails)
	repo.TouchedPaths(ctx, emails)
	changed := map[string]bool{}
	for h := range commits {
		changed[h] = true
	}
	repo.ChangedPaths(ctx, changed)
	repo.FixCommits(ctx)
	repo.FixedLines(ctx, parent, func(string) bool { return true })
	if blobs, err := repo.OpenBlobs(ctx); err == nil {
		blobs.Show(head, "a.go")
		blobs.Close()
	}

	if data, err := os.ReadFile(marker); err == nil {
		t.Fatalf("the repository's config ran a program %d times", strings.Count(string(data), "\n"))
	}
}

// gitOut runs git in dir with stdin and returns its output.
func gitOut(t *testing.T, dir, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return string(out)
}
