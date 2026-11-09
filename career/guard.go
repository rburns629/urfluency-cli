package career

import (
	"fmt"
	"regexp"
	"slices"
)

// Guardrails for what reaches Vertex. The API makes the call, but the request
// comes from the user's machine, where anyone can edit it. So these hold
// whoever builds the request: the CLI runs them before sending, and the API
// runs the same ones on receipt. The engine adds its own on top (question
// templates, and checks on every answer).

// FactKinds are the only kinds of question and fact.
var FactKinds = []string{FactOwnership, FactShipped, FactScale, FactOutcome, FactPartner, FactUnseen}

// instructionRe matches text that tries to instruct the model rather than
// describe work: telling it to drop its instructions, naming its prompt,
// casting it as someone else, or a chat format's turn and role markers. It is
// narrow on purpose, so an engineer's own words about their work pass.
var instructionRe = regexp.MustCompile(`(?i)` +
	`\b(ignore|disregard|forget)\s+(all\s+|any\s+|the\s+|your\s+|these\s+|those\s+)?instructions?\b` +
	`|\b(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+|your\s+|these\s+|those\s+)?(previous|prior|above|earlier|preceding|system|original)\s+(instructions?|prompts?|rules|directions|guidelines|messages)\b` +
	`|\bdo\s+not\s+follow\s+(the\s+|your\s+|these\s+|those\s+)?(instructions?|rules|guidelines)\b` +
	`|\bsystem\s+(prompt|instructions?)\b|\b(developer|hidden)\s+(prompt|message|instructions?)\b` +
	`|\b(new|updated|real|actual|additional)\s+instructions?\s*:` +
	`|\byou\s+are\s+now\s+(an?|the|my)\b|\bpretend\s+(to\s+be|you\s+are)\b|\bfrom\s+now\s+on,?\s+you\b` +
	`|\b(respond|answer|reply)\s+only\s+with\b` +
	`|<\|[a-z_]*\|>|\[/?INST\]|<</?SYS>>|(?m:^\s*(system|assistant)\s*:)` + "|```")

// InstructionLike reports whether s reads as instructions to the model.
func InstructionLike(s string) bool { return instructionRe.MatchString(s) }

// Suspect says why s may not reach Vertex or come back from it, or "": it
// identifies code, people, or systems, or it reads as instructions to the
// model.
func Suspect(s string) string {
	if why := identifying(s); why != "" {
		return why
	}
	if InstructionLike(s) {
		return "text that reads as instructions to the AI model"
	}
	return ""
}

// ErrInstructions marks a request refused for text that reads as
// instructions to the model.
var ErrInstructions = fmt.Errorf("career request reads as instructions to the AI model")

// Target limits: what LearnTarget can find in a real profile or resume.
var (
	targetOpenings = []string{"", "noun phrase", "verb", "first person"}
	sectionRe      = regexp.MustCompile(`^[A-Z][A-Za-z &/]{2,40}$`)
)

// validTarget checks a draft's target structure: only rules, never text, as
// LearnTarget keeps them.
func validTarget(t *Target, kind string) error {
	if t == nil {
		return nil
	}
	switch {
	case t.Kind != kind:
		return fmt.Errorf("target kind %q doesn't match the draft's %q", t.Kind, kind)
	case !slices.Contains(targetOpenings, t.Opening):
		return fmt.Errorf("target opening %q", t.Opening)
	case t.ParagraphsPerRole < 0 || t.ParagraphsPerRole > 6, t.BulletsPerRole < 0 || t.BulletsPerRole > 12,
		t.SkillsPerRole < 0 || t.SkillsPerRole > 20, t.SentenceWords < 0 || t.SentenceWords > 80,
		t.MinChars < 0 || t.MaxChars < 0 || t.MaxChars > AboutLimit || (t.MaxChars > 0 && t.MinChars > t.MaxChars):
		return fmt.Errorf("target counts are out of range")
	case len(t.Sections) > 12:
		return fmt.Errorf("target has %d sections, more than a resume has", len(t.Sections))
	}
	for _, s := range t.Sections {
		if !sectionRe.MatchString(s) || InstructionLike(s) {
			return fmt.Errorf("target section %q isn't a section heading", s)
		}
	}
	return nil
}
