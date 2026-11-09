package career

import (
	"regexp"
	"sort"
	"strings"
)

// Redaction runs on the machine before anything is sent, and lives here, in
// the public CLI, so anyone can read what it removes. It removes internal
// hostnames, IP addresses, email addresses, cloud project and account IDs,
// URLs, ticket keys, and token-shaped strings, and replaces the internal names
// the user marked.

var (
	redactURL   = regexp.MustCompile(`(?i)\b(?:https?|ssh|git|ftp)://\S+|\bgit@\S+|\bwww\.\S+`)
	redactEmail = emailRe
	redactIP    = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b`)
	// Hostnames: two or more labels with a known suffix or an internal one.
	redactHost = regexp.MustCompile(`(?i)\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.(?:com|net|org|io|dev|cloud|internal|local|corp|lan|intra|intranet|site|app|biz|co|us|eu|se|de|uk|cn)\b`)
	// Ticket keys such as ABC-123.
	redactTicket = regexp.MustCompile(`\b[A-Z][A-Z0-9]{1,9}-\d{1,6}\b`)
	// Cloud IDs: UUIDs (Azure subscriptions and tenants), 12-digit AWS
	// accounts, and GCP project IDs, which have a hyphen and end in digits.
	redactUUID    = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	redactAccount = regexp.MustCompile(`\b\d{12}\b`)
	redactProject = regexp.MustCompile(`\b[a-z][a-z0-9]*(?:-[a-z0-9]+)*-\d{3,}\b`)
	// Token-shaped strings: known prefixes, and long runs of base64 or hex
	// with digits in them.
	secretRe   = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|xox[abpr]-[A-Za-z0-9-]{10,}|sk_(?:live|test)_[A-Za-z0-9]{16,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`)
	redactLong = regexp.MustCompile(`\b[A-Za-z0-9+/_=-]{32,}\b`)
	redactHash = regexp.MustCompile(`\b[0-9a-f]{12,64}\b`)
	spaces     = regexp.MustCompile(`[ \t]{2,}`)
)

// technologyNames look like hostnames but name software.
var technologyNames = map[string]bool{"asp.net": true, "ado.net": true, "vb.net": true, "socket.io": true, "ent.io": true}

// standardPrefixes look like ticket keys but name standards and algorithms,
// as in SHA-256 or UTF-8.
var standardPrefixes = map[string]bool{"SHA": true, "UTF": true, "ISO": true, "AES": true, "RSA": true, "TLS": true, "SSL": true,
	"HTTP": true, "IPV": true, "EC": true, "PCI": true, "WCAG": true, "IEEE": true, "RFC": true, "OAUTH": true, "MP": true, "ES": true}

// Placeholders that replace what redaction removes.
const (
	Removed = "[removed]"
	Host    = "[host]"
	Ticket  = "[ticket]"
)

// Redact removes identifying text from s and replaces each name in names with
// its replacement: the token for an assist request, the generic description
// for a pack. Longer names are replaced first, so "Atlas API" wins over
// "Atlas".
func Redact(s string, names map[string]string) string {
	s = replaceNames(s, names)
	// Text that reads as instructions to the model never leaves the machine:
	// a commit subject or answer can't redirect what Vertex is asked to do.
	s = instructionRe.ReplaceAllString(s, Removed)
	s = secretRe.ReplaceAllString(s, Removed)
	s = redactURL.ReplaceAllString(s, Removed)
	s = redactEmail.ReplaceAllString(s, Removed)
	s = redactUUID.ReplaceAllString(s, Removed)
	s = redactIP.ReplaceAllString(s, Host)
	s = redactHost.ReplaceAllStringFunc(s, func(m string) string {
		if technologyNames[strings.ToLower(m)] {
			return m
		}
		return Host
	})
	s = redactTicket.ReplaceAllStringFunc(s, func(m string) string {
		if standardPrefixes[strings.ToUpper(m[:strings.IndexByte(m, '-')])] {
			return m
		}
		return Ticket
	})
	s = redactAccount.ReplaceAllString(s, Removed)
	s = redactProject.ReplaceAllString(s, Removed)
	s = redactLong.ReplaceAllStringFunc(s, func(m string) string {
		if strings.ContainsAny(m, "0123456789") {
			return Removed
		}
		return m
	})
	s = redactHash.ReplaceAllStringFunc(s, func(m string) string {
		if strings.ContainsAny(m, "0123456789") && strings.ContainsAny(m, "abcdef") {
			return Removed
		}
		return m
	})
	s = localPath(s)
	return strings.TrimSpace(spaces.ReplaceAllString(s, " "))
}

// localPath removes paths that start at a home, temporary, or drive folder,
// up to the next space.
func localPath(s string) string {
	for {
		loc := pathRe.FindStringSubmatchIndex(s)
		if loc == nil {
			return s
		}
		start := loc[4] // the path itself, after the boundary character
		end := start
		for end < len(s) && s[end] != ' ' && s[end] != '\n' && s[end] != '\t' {
			end++
		}
		s = s[:start] + Removed + s[end:]
	}
}

func replaceNames(s string, names map[string]string) string {
	if len(names) == 0 {
		return s
	}
	keys := make([]string, 0, len(names))
	for k := range names {
		if strings.TrimSpace(k) != "" {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	// Each match becomes a placeholder, a private-use character that no name
	// can match, and the replacements go in at the end, so a replacement that
	// contains its own name, as "Billing" in "the billing service" does, is
	// never matched again.
	held := make([]string, len(keys))
	for i, k := range keys {
		re := regexp.MustCompile(`(?i)(^|[^\pL\pN])` + regexp.QuoteMeta(k) + `($|[^\pL\pN])`)
		held[i] = string(rune(0xF0000 + i))
		// Repeat: adjacent matches share a boundary character.
		for re.MatchString(s) {
			s = re.ReplaceAllString(s, "${1}"+held[i]+"${2}")
		}
	}
	for i, k := range keys {
		s = strings.ReplaceAll(s, held[i], names[k])
	}
	return s
}

// ForAssist maps each name the user has not marked public to its token.
func ForAssist(names []Name) map[string]string {
	out := map[string]string{}
	for _, n := range names {
		if !n.Public {
			out[n.Found] = n.Token
		}
	}
	return out
}

// ForPack maps each name the user has not marked public to its generic
// description, or to a plain "an internal system" when it has none.
func ForPack(names []Name) map[string]string {
	out := map[string]string{}
	for _, n := range names {
		if n.Public {
			continue
		}
		g := strings.TrimSpace(n.Generic)
		if g == "" {
			g = "an internal system"
		}
		out[n.Found] = g
	}
	return out
}

var distinctiveName = regexp.MustCompile(`[-_.0-9]|[a-z][A-Z]`)

// WithRepositories adds each distinctive repository name, one with a hyphen,
// underscore, dot, digit, or inner capital such as cp-orbit-ns-deploy, to
// names as "the project": commit subjects often name their repository. Plain
// words, such as "returns", are left, since they read as ordinary words.
func WithRepositories(names map[string]string, ev Evidence) map[string]string {
	for _, r := range ev.Repos {
		if len(r.Name) >= 3 && distinctiveName.MatchString(r.Name) {
			if _, ok := names[r.Name]; !ok {
				names[r.Name] = "the project"
			}
		}
	}
	return names
}

// RedactPack redacts every free-text string in a pack in place.
func RedactPack(p *Pack, names map[string]string) {
	for i := range p.Roles {
		r := &p.Roles[i]
		r.Title, r.Note, r.Company = Redact(r.Title, names), Redact(r.Note, names), Redact(r.Company, names)
	}
	for _, fs := range []*[]PackFeature{&p.Features, &p.Side} {
		for i := range *fs {
			f := &(*fs)[i]
			f.Summary = Redact(f.Summary, names)
			for j := range f.Technologies {
				f.Technologies[j] = Redact(f.Technologies[j], names)
			}
		}
	}
	for i := range p.Facts {
		p.Facts[i].Text = Redact(p.Facts[i].Text, names)
	}
	for i := range p.Skills {
		p.Skills[i] = Redact(p.Skills[i], names)
	}
}

// RedactAssist redacts every free-text string in an assist request in place.
func RedactAssist(a *AssistRequest, names map[string]string) {
	for i := range a.Features {
		f := &a.Features[i]
		f.Purpose = Redact(f.Purpose, names)
		for j := range f.Subjects {
			f.Subjects[j] = Redact(f.Subjects[j], names)
		}
	}
	for i := range a.Questions {
		a.Questions[i].Text = Redact(a.Questions[i].Text, names)
	}
	for i := range a.Names {
		a.Names[i].Context = Redact(a.Names[i].Context, names)
	}
}
