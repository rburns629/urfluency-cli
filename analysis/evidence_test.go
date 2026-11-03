package analysis

import "testing"

// A function's evidence is bounded, so deep nesting cannot flood the findings.
func TestEvidenceIsBounded(t *testing.T) {
	if n := len(EvidenceOf("a.go", 1, 5_000_000)); n != 1+maxBranchEvidence {
		t.Errorf("evidence for a huge complexity = %d findings, want %d", n, 1+maxBranchEvidence)
	}
	if n := len(EvidenceOf("a.go", 1, -3)); n != 1 {
		t.Errorf("evidence for a negative complexity = %d findings, want 1", n)
	}
}
