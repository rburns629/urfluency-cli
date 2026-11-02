package all

import (
	"os"
	"testing"

	"github.com/rburns629/urfluency-cli/analysis"
)

// Every analyzer package under analyzers/ must be registered here.
func TestRegistersEveryAnalyzer(t *testing.T) {
	entries, err := os.ReadDir("..")
	if err != nil {
		t.Fatal(err)
	}
	registered := map[string]bool{}
	for _, a := range analysis.Analyzers() {
		registered[a.Language()] = true
	}
	for _, s := range analysis.Scanners() {
		registered[s.Name()] = true
	}
	// Package names that differ from the catalog language they register.
	language := map[string]string{"golang": "go"}
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "all" || e.Name() == "fuzz" {
			continue
		}
		name := e.Name()
		if l, ok := language[name]; ok {
			name = l
		}
		if !registered[name] {
			t.Errorf("analyzers/%s is not registered", e.Name())
		}
	}
}
