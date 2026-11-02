package report

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// TermSafe escapes control characters in text taken from a scanned
// repository, such as a file name, a package name, or an excerpt, before it is
// printed to a terminal. ESC and the other C0 and C1 controls could otherwise
// move the cursor, rewrite the screen, or hide a verdict. Each is shown as an
// escape such as \x1b; invalid UTF-8, which some terminals read as C1, is
// replaced.
func TermSafe(s string) string {
	if !strings.ContainsFunc(s, unsafeRune) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			b.WriteRune(utf8.RuneError)
		case unsafeRune(r):
			fmt.Fprintf(&b, "\\x%02x", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func unsafeRune(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == utf8.RuneError
}
