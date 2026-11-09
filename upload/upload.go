// Package upload defines what `urfluency upload` sends to urfluency.com: a
// report's summary and combined result, with version information. It is the
// contract between the CLI and the service, so both validate with it.
//
// A payload carries ratings, counts, rule and library names, the summary's
// sentences, and the facts urfluency.com's official model scores (package
// facts). It never carries source code, prompt text, repository names, file
// paths, commit hashes, email addresses, or secret values; Validate rejects
// payloads that look like they do.
package upload

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Format versions the payload. Format 2 added facts; the service refuses
// format 1.
const Format = "2"

// MaxBytes bounds an encoded payload.
const MaxBytes = 1 << 20

// Tiers a payload can claim. The CLI only sends self-reported results; the
// service assigns the tiers it can verify itself.
const (
	SelfReported = "self-reported"
	Declared     = "declared"
)

// Payload is one upload.
type Payload struct {
	Format  string `json:"format"`
	Tool    string `json:"tool"`          // CLI version
	Report  string `json:"report_format"` // report schema the summary follows
	Catalog string `json:"catalog"`       // rule catalog version
	Model   string `json:"model"`         // proficiency model version
	Tier    string `json:"tier"`
	Since   string `json:"since"` // "all" or YYYY-MM-DD
	// Summary and Combined are the report's "summary" and "combined" objects.
	Summary  json.RawMessage `json:"summary"`
	Combined json.RawMessage `json:"combined"`
	// Facts are the counts the official model scores, a facts.Facts.
	Facts json.RawMessage `json:"facts"`
}

// forbiddenKeys name fields that would identify code or people. A report's
// summary and combined result never have them; their presence means the
// payload was not built from those parts.
var forbiddenKeys = map[string]bool{
	"locations": true, "location": true, "path": true, "paths": true, "file": true,
	"repository": true, "repo": true, "label": true, "commit": true, "head": true,
	"email": true, "emails": true, "author": true, "authors": true, "source": true,
	"code": true, "prompt": true, "secret": true, "value": true,
}

var (
	emailRe = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	// localPathRe matches the start of a local path anywhere but inside a word
	// or URL: home folders, temporary and mounted folders, and Windows drives
	// with either slash.
	localPathRe = regexp.MustCompile(`(^|[^A-Za-z0-9_.-])(/Users/|/home/|/root/|~/|/tmp/|/var/folders/|/private/|/mnt/|/Volumes/|[A-Za-z]:[\\/])`)
	// hashRe matches full SHA-1 and SHA-256 commit hashes in either case.
	hashRe  = regexp.MustCompile(`\b([0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b`)
	sinceRe = regexp.MustCompile(`^(all|\d{4}-\d{2}-\d{2})$`)
)

// Validate is Validate(p), so a payload carries its own schema check.
func (p Payload) Validate() error { return Validate(p) }

// Validate checks a payload's versions, size, and shape, and rejects anything
// that looks identifying: forbidden field names, email addresses, local paths,
// or commit hashes in any string, map key, or version field.
func Validate(p Payload) error {
	if p.Format != Format {
		return fmt.Errorf("upload format %q, want %q", p.Format, Format)
	}
	if p.Tier != SelfReported && p.Tier != Declared {
		return fmt.Errorf("tier %q cannot be claimed by the CLI", p.Tier)
	}
	for name, v := range map[string]string{"tool": p.Tool, "report_format": p.Report, "catalog": p.Catalog, "model": p.Model, "since": p.Since} {
		if v == "" || len(v) > 64 {
			return fmt.Errorf("%s must be 1 to 64 characters", name)
		}
		if why := identifying(v); why != "" {
			return fmt.Errorf("%w: %s in %s", ErrIdentifying, why, name)
		}
	}
	if !sinceRe.MatchString(p.Since) {
		return fmt.Errorf("since must be \"all\" or a date, not %q", p.Since)
	}
	if len(p.Summary)+len(p.Combined)+len(p.Facts) > MaxBytes {
		return fmt.Errorf("payload over %d bytes", MaxBytes)
	}
	for name, raw := range map[string]json.RawMessage{"summary": p.Summary, "combined": p.Combined, "facts": p.Facts} {
		var v any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if _, ok := v.(map[string]any); !ok {
			return fmt.Errorf("%s must be an object", name)
		}
		if err := check(name, v); err != nil {
			return err
		}
	}
	return nil
}

// ErrIdentifying marks a payload rejected for carrying identifying data.
var ErrIdentifying = errors.New("payload carries identifying data")

func check(at string, v any) error {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if forbiddenKeys[strings.ToLower(k)] {
				return fmt.Errorf("%w: field %s.%s", ErrIdentifying, at, k)
			}
			// Keys are checked like values: a map keyed by path or address
			// leaks as much as a list of them.
			if why := identifying(k); why != "" {
				return fmt.Errorf("%w: %s in a key of %s", ErrIdentifying, why, at)
			}
			if err := check(at+"."+k, child); err != nil {
				return err
			}
		}
	case []any:
		for i, child := range t {
			if err := check(fmt.Sprintf("%s[%d]", at, i), child); err != nil {
				return err
			}
		}
	case string:
		if why := identifying(t); why != "" {
			return fmt.Errorf("%w: %s in %s", ErrIdentifying, why, at)
		}
	}
	return nil
}

// identifying names what in s identifies code or people, or returns "".
func identifying(s string) string {
	switch {
	case emailRe.MatchString(s):
		return "email address"
	case localPathRe.MatchString(s):
		return "local path"
	case hashRe.MatchString(s):
		return "commit hash"
	}
	return ""
}
