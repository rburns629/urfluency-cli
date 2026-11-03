package analysis

import "strings"

// Evidence is how much logic a language's owned code holds: the functions it
// defines and their cognitive complexity, the branches and loops a function's
// reader follows. A rating's ceiling rises with it, so a small project full of
// logic shows more than many lines of declarations.
type Evidence struct {
	Functions int
	Branches  int
}

// Evidence findings carry one function, and its complexity, from an analyzer
// to the engine, which counts them on owned lines as it counts idioms.
const (
	EvidenceFunction = "evidence.function"
	EvidenceBranch   = "evidence.branch"
)

// EvidenceOf returns the findings that record a function at line with the
// given cognitive complexity: one for the function and one per point of
// complexity.
func EvidenceOf(path string, line, complexity int) []Finding {
	out := make([]Finding, 0, 1+complexity)
	out = append(out, Finding{Rule: EvidenceFunction, Path: path, Line: line, Positive: true})
	for range complexity {
		out = append(out, Finding{Rule: EvidenceBranch, Path: path, Line: line, Positive: true})
	}
	return out
}

func isEvidence(rule string) bool { return strings.HasPrefix(rule, "evidence.") }
