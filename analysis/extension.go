package analysis

import "context"

// An Extension adds checks to a language's analyzer. The engine gives it the
// same files and counts its findings on owned lines as it does the
// analyzer's. Extensions register in init, as analyzers do; the community
// build has none.
type Extension interface {
	// Language is the analyzer's language, such as "python".
	Language() string
	Analyze(ctx context.Context, files []File) ([]Finding, error)
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
// extensions.
func withExtensions(a Analyzer) func(context.Context, []File) ([]Finding, error) {
	var ext []Extension
	for _, e := range extensions {
		if e.Language() == a.Language() {
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
