package report

import "testing"

func TestTermSafe(t *testing.T) {
	for in, want := range map[string]string{
		"src/app.go":                    "src/app.go",
		"café.go":                       "café.go",
		"a\x1b[2J\x1b[Hb.go":            `a\x1b[2J\x1b[Hb.go`,
		"\x1b]8;;https://x.example\x07": `\x1b]8;;https://x.example\x07`,
		"line\nbreak\ttab":              `line\x0abreak\x09tab`,
		"c1\u009bJ":                     `c1\x9bJ`,
		"raw\x9bbyte":                   "raw�byte",
	} {
		if got := TermSafe(in); got != want {
			t.Errorf("TermSafe(%q) = %q, want %q", in, got, want)
		}
	}
}
