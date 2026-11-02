package testutil

import (
	"os"
	"path/filepath"
	"testing"
)

// Run from a Git hook, GIT_DIR and GIT_INDEX_FILE are set for the real
// repository; the helper must ignore them.
func TestRepoIgnoresInheritedGitVariables(t *testing.T) {
	real := t.TempDir()
	t.Setenv("GIT_DIR", filepath.Join(real, ".git"))
	t.Setenv("GIT_INDEX_FILE", filepath.Join(real, "index"))
	r := NewRepo(t)
	r.Commit("a@example.com", "", map[string]string{"a.go": "package a\n"})
	if _, err := os.Stat(filepath.Join(r.Dir, ".git")); err != nil {
		t.Errorf("the test repository has no .git: %v", err)
	}
	if entries, _ := os.ReadDir(real); len(entries) > 0 {
		t.Errorf("git wrote to the inherited GIT_DIR: %v", entries)
	}
}
