package analysis

import (
	"context"
	"time"
)

// An Extension adds checks to a language's analyzer. The engine gives it the
// same files and counts its findings on owned lines as it does the
// analyzer's. Extensions register in init, as analyzers do; the community
// build has none.
type Extension interface {
	// Language is the analyzer's language, such as "python".
	Language() string
	Analyze(ctx context.Context, files []File) ([]Finding, error)
}

// A ProjectExtension reads all of a project's files in its language once,
// before they are analyzed one at a time, and returns the Extension that
// analyzes them knowing what it learned: that the project validates request
// bodies with a schema library in its route files, say, when a controller
// file alone cannot show it. The engine runs ForProject under the same
// recovery and time budget as one file's analysis; if it panics or runs out
// of time, the files are analyzed by the extension itself, without project
// context.
type ProjectExtension interface {
	Extension
	ForProject(ctx context.Context, files []File) Extension
}

var (
	extensions []Extension
	engineName = "community"
)

// RegisterExtension adds an extension's checks to its language.
func RegisterExtension(e Extension) { extensions = append(extensions, e) }

// SetEngine names the engine a build runs, as uploads report it; the
// community build is "community".
func SetEngine(name string) { engineName = name }

// Engine is the name of the engine this build runs.
func Engine() string { return engineName }

// withExtensions returns an analyzer's Analyze followed by its language's
// extensions, each given the project's files first if it reads them.
func withExtensions(ctx context.Context, a Analyzer, files []File) func(context.Context, []File) ([]Finding, error) {
	var ext []Extension
	for _, e := range extensions {
		if e.Language() == a.Language() {
			if pe, ok := e.(ProjectExtension); ok {
				e = forProject(ctx, pe, files)
			}
			ext = append(ext, e)
		}
	}
	if len(ext) == 0 {
		return a.Analyze
	}
	return func(ctx context.Context, files []File) ([]Finding, error) {
		out, err := a.Analyze(ctx, files)
		if err != nil {
			return out, err
		}
		for _, e := range ext {
			more, err := e.Analyze(ctx, files)
			if err != nil {
				return out, err
			}
			out = append(out, more...)
		}
		return out, nil
	}
}

// forProject runs pe.ForProject with recovery and a time budget, falling
// back to pe itself.
func forProject(ctx context.Context, pe ProjectExtension, files []File) Extension {
	done := make(chan Extension, 1) // buffered, so an abandoned call can still finish
	go func() {
		defer func() {
			if recover() != nil {
				done <- nil
			}
		}()
		done <- pe.ForProject(ctx, files)
	}()
	timer := time.NewTimer(AnalysisBudget)
	defer timer.Stop()
	select {
	case e := <-done:
		if e != nil {
			return e
		}
	case <-timer.C:
	case <-ctx.Done():
	}
	return pe
}
