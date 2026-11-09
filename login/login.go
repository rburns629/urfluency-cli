// Package login holds the request bodies of urfluency login, shared by the CLI,
// which checks each one before sending it, and the API, which checks it again
// on receipt. One definition on both sides keeps them from drifting apart.
package login

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Client is the only client a login names.
const Client = "urfluency-cli"

// MaxDevice bounds a device name, the longest a hostname can be. The API
// shows at most 64 characters of it.
const MaxDevice = 253

var (
	// versionRE is a release version, like 1.9.1 or 1.10.0-rc.1, or a
	// development build's "dev".
	versionRE = regexp.MustCompile(`^(dev|[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}([-+][0-9A-Za-z.-]{1,24})?)$`)
	// challengeRE is a base64url SHA-256 (43 characters).
	challengeRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	// stateRE is the CLI's state value.
	stateRE = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	// loopbackRE is the only redirect a login accepts: the CLI's own listener.
	loopbackRE = regexp.MustCompile(`^http://127\.0\.0\.1:([0-9]{4,5})/callback$`)
	// codeRE is the login code the API issues: 32 random bytes, base64url.
	codeRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	// verifierRE is a PKCE code verifier (RFC 7636, section 4.1).
	verifierRE = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
)

// Start is POST /v1/auth/cli: it opens a login for the browser to approve.
type Start struct {
	Client    string `json:"client"`
	Version   string `json:"version"`
	Device    string `json:"device"`
	Challenge string `json:"code_challenge"`
	Method    string `json:"code_challenge_method"`
	PublicKey string `json:"public_key"`
	Redirect  string `json:"redirect_uri"`
	State     string `json:"state"`
}

// Validate checks every field. Its messages are the API's answers.
func (s Start) Validate() error {
	switch {
	case s.Client != Client:
		return errors.New("client must be " + Client)
	case !versionRE.MatchString(s.Version):
		return errors.New("version must be a urfluency version, like 1.9.1")
	case !validDevice(s.Device):
		return errors.New("device must be a name of at most 253 characters, without control characters")
	case s.Method != "S256" || !challengeRE.MatchString(s.Challenge):
		return errors.New("code_challenge must be an S256 PKCE challenge")
	case !ValidPublicKey(s.PublicKey):
		return errors.New("public_key must be a base64url Ed25519 key")
	case s.Redirect != "" && !ValidLoopback(s.Redirect):
		return errors.New("redirect_uri must be http://127.0.0.1:PORT/callback")
	case s.State != "" && !stateRE.MatchString(s.State), s.Redirect != "" && s.State == "":
		return errors.New("state must be 16 to 128 base64url characters")
	}
	return nil
}

// Token is POST /v1/auth/cli/{id}/token: it trades the approved login's code
// and the PKCE verifier for a token.
type Token struct {
	Code     string `json:"code"`
	Verifier string `json:"code_verifier"`
}

// Validate checks both fields.
func (t Token) Validate() error {
	if !codeRE.MatchString(t.Code) || !verifierRE.MatchString(t.Verifier) {
		return errors.New("expected {code, code_verifier}")
	}
	return nil
}

// ValidPublicKey reports whether k is a base64url Ed25519 public key.
func ValidPublicKey(k string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(k)
	return err == nil && len(raw) == ed25519.PublicKeySize
}

// ValidLoopback reports whether redirect is the CLI's own listener on an
// unprivileged port.
func ValidLoopback(redirect string) bool {
	m := loopbackRE.FindStringSubmatch(redirect)
	if m == nil {
		return false
	}
	port, err := strconv.Atoi(m[1])
	return err == nil && port >= 1024 && port <= 65535
}

// Device makes a device name fit the schema: control and format characters
// become spaces, runs of space collapse, and it is cut to MaxDevice.
func Device(name string) string {
	out := make([]rune, 0, len(name))
	space := false
	for _, r := range name {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.IsSpace(r) {
			space = len(out) > 0
			continue
		}
		if space {
			out = append(out, ' ')
			space = false
		}
		out = append(out, r)
	}
	if len(out) > MaxDevice {
		out = out[:MaxDevice]
	}
	return strings.TrimRight(string(out), " ")
}

func validDevice(s string) bool {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > MaxDevice {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}
