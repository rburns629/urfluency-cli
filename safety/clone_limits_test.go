package safety

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The tests serve repositories from a local plain-HTTP server; production
// clones are HTTPS only.
func init() { testGitConfig = []string{"protocol.http.allow=always"} }

// serveRepo builds a bare repository with build and serves it over HTTP.
func serveRepo(t *testing.T, build func(git func(args ...string) string, work string)) string {
	t.Helper()
	srv := httptest.NewServer(repoHandler(t, build))
	t.Cleanup(srv.Close)
	return srv.URL + "/repo.git"
}

// repoHandler builds a bare repository with build and returns a handler
// that serves it as /repo.git.
func repoHandler(t *testing.T, build func(git func(args ...string) string, work string)) http.Handler {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	backend := filepath.Join(strings.TrimSpace(gitOutput(t, "--exec-path")), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git-http-backend not available")
	}
	root := t.TempDir()
	work := filepath.Join(root, "work")
	os.MkdirAll(work, 0o755)
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = work
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q", "-b", "main")
	build(git, work)
	if out, err := exec.Command("git", "clone", "-q", "--bare", work, filepath.Join(root, "repo.git")).CombinedOutput(); err != nil {
		t.Fatalf("bare clone: %v\n%s", err, out)
	}
	return &cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}}
}

// slowWriter sends a response in small, delayed pieces, as a large download
// arrives, and counts what it sent.
type slowWriter struct {
	http.ResponseWriter
	sent *atomic.Int64
}

func (w slowWriter) Write(b []byte) (int, error) {
	n := 0
	for len(b) > 0 {
		piece := b[:min(len(b), 32<<10)]
		time.Sleep(10 * time.Millisecond)
		m, err := w.ResponseWriter.Write(piece)
		n += m
		w.sent.Add(int64(m))
		if err != nil {
			return n, err
		}
		w.ResponseWriter.(http.Flusher).Flush()
		b = b[len(piece):]
	}
	return n, nil
}

func TestCloneRefusesALargeCheckoutBeforeWritingIt(t *testing.T) {
	url := serveRepo(t, func(git func(...string) string, work string) {
		// Zeros compress to almost nothing, as a checkout bomb would.
		os.WriteFile(filepath.Join(work, "big.bin"), make([]byte, 4<<20), 0o644)
		git("add", "-A")
		git("commit", "-q", "-m", "big")
	})
	dest := filepath.Join(t.TempDir(), "clone")
	limits := DefaultCloneLimits
	limits.MaxBytes = 1 << 20
	if err := Clone(context.Background(), url, dest, limits); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Clone: %v, want ErrTooLarge", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "big.bin")); err == nil {
		t.Error("the oversized file was written before the clone was refused")
	}
}

func TestCloneStopsAnOversizedDownload(t *testing.T) {
	url := serveRepo(t, func(git func(...string) string, work string) {
		// Random bytes do not compress, so the download is as large as the file.
		big := make([]byte, 4<<20)
		rand.Read(big)
		os.WriteFile(filepath.Join(work, "big.bin"), big, 0o644)
		git("add", "-A")
		git("commit", "-q", "-m", "big")
	})
	dest := filepath.Join(t.TempDir(), "clone")
	limits := DefaultCloneLimits
	limits.MaxBytes, limits.MaxDownload = 1<<30, 1<<20
	if err := Clone(context.Background(), url, dest, limits); !errors.Is(err, ErrDownloadTooLarge) || !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Clone: %v, want ErrDownloadTooLarge", err)
	}
	limits.MaxDownload = 8 << 20
	if err := Clone(context.Background(), url, filepath.Join(t.TempDir(), "clone"), limits); err != nil {
		t.Fatalf("Clone within the download limit: %v", err)
	}
}

func TestCloneStopsADownloadBeforeItEnds(t *testing.T) {
	const size = 8 << 20
	repo := repoHandler(t, func(git func(...string) string, work string) {
		big := make([]byte, size)
		rand.Read(big)
		os.WriteFile(filepath.Join(work, "big.bin"), big, 0o644)
		git("add", "-A")
		git("commit", "-q", "-m", "big")
	})
	var sent atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		repo.ServeHTTP(slowWriter{w, &sent}, r)
	}))
	defer srv.Close()
	limits := DefaultCloneLimits
	limits.MaxBytes, limits.MaxDownload = 1<<30, 1<<20
	if err := Clone(context.Background(), srv.URL+"/repo.git", filepath.Join(t.TempDir(), "clone"), limits); !errors.Is(err, ErrDownloadTooLarge) {
		t.Fatalf("Clone: %v, want ErrDownloadTooLarge", err)
	}
	// About 3 MB a second arrives, so Git is stopped long before the end.
	if n := sent.Load(); n >= size/2 {
		t.Errorf("the server sent %d of %d bytes before the clone was stopped", n, size)
	}
}

func TestCloneRefusesTooManyFilesBeforeWritingThem(t *testing.T) {
	url := serveRepo(t, func(git func(...string) string, work string) {
		for i := range 20 {
			os.WriteFile(filepath.Join(work, fmt.Sprintf("f%d", i)), nil, 0o644)
		}
		git("add", "-A")
		git("commit", "-q", "-m", "many")
	})
	dest := filepath.Join(t.TempDir(), "clone")
	limits := DefaultCloneLimits
	limits.MaxFiles = 10
	if err := Clone(context.Background(), url, dest, limits); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Clone: %v, want ErrTooLarge", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "f0")); err == nil {
		t.Error("files were written before the clone was refused")
	}
}

func TestCloneRejectsMalformedObjects(t *testing.T) {
	url := serveRepo(t, func(git func(...string) string, work string) {
		// A tree with an entry named .git, the shape of past Git exploits that
		// overwrite repository configuration on checkout; fsck rejects it.
		blob := git("hash-object", "-w", "--stdin")
		cmd := exec.Command("git", "mktree")
		cmd.Dir = work
		cmd.Stdin = strings.NewReader("100644 blob " + blob + "\t.git\n")
		out, err := cmd.Output()
		if err != nil {
			t.Skipf("this Git refuses to write the tree itself: %v", err)
		}
		commit := git("commit-tree", strings.TrimSpace(string(out)), "-m", "evil")
		git("update-ref", "refs/heads/main", commit)
	})
	dest := filepath.Join(t.TempDir(), "clone")
	err := Clone(context.Background(), url, dest, DefaultCloneLimits)
	if err == nil {
		t.Fatal("a repository with a .git tree entry was cloned")
	}
	if !strings.Contains(err.Error(), "fsck") && !strings.Contains(err.Error(), "hasDotgit") && !strings.Contains(err.Error(), "invalid object") {
		t.Errorf("refused for another reason than the object check: %v", err)
	}
}

func TestCloneRefusesPlainHTTPInProduction(t *testing.T) {
	url := serveRepo(t, func(git func(...string) string, work string) {
		os.WriteFile(filepath.Join(work, "a.txt"), []byte("a"), 0o644)
		git("add", "-A")
		git("commit", "-q", "-m", "a")
	})
	saved := testGitConfig
	testGitConfig = nil
	defer func() { testGitConfig = saved }()
	if err := Clone(context.Background(), url, filepath.Join(t.TempDir(), "clone"), DefaultCloneLimits); err == nil {
		t.Fatal("cloned over plain HTTP with the production configuration")
	}
}

func TestCloneWithAuthorization(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	backend := filepath.Join(strings.TrimSpace(gitOutput(t, "--exec-path")), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git-http-backend not available")
	}
	root := t.TempDir()
	work := filepath.Join(root, "work")
	os.MkdirAll(work, 0o755)
	run := func(dir string, args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run(work, "init", "-q", "-b", "main")
	os.WriteFile(filepath.Join(work, "a.txt"), []byte("private"), 0o644)
	run(work, "add", "-A")
	run(work, "commit", "-q", "-m", "a")
	run(root, "clone", "-q", "--bare", work, filepath.Join(root, "repo.git"))
	// A private repository: only requests with the token are served.
	const header = "Basic eC1hY2Nlc3MtdG9rZW46c2VjcmV0"
	git := &cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != header {
			w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		git.ServeHTTP(w, r)
	}))
	defer srv.Close()

	if err := Clone(context.Background(), srv.URL+"/repo.git", filepath.Join(t.TempDir(), "c"), DefaultCloneLimits); err == nil {
		t.Fatal("cloned a private repository without the token")
	}
	dest := filepath.Join(t.TempDir(), "c")
	limits := DefaultCloneLimits
	limits.Authorization = header
	if err := Clone(context.Background(), srv.URL+"/repo.git", dest, limits); err != nil {
		t.Fatalf("clone with the token: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "a.txt")); string(b) != "private" {
		t.Errorf("checkout = %q", b)
	}
	if cfg, _ := os.ReadFile(filepath.Join(dest, ".git", "config")); strings.Contains(string(cfg), "eC1hY2Nl") || strings.Contains(string(cfg), "extraHeader") {
		t.Errorf("the token was saved in the clone's configuration:\n%s", cfg)
	}
}
