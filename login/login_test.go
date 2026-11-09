package login

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func key(t *testing.T) string {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(pub)
}

func good(t *testing.T) Start {
	return Start{Client: Client, Version: "1.9.1", Device: "Roberts-MacBook-Pro", Challenge: strings.Repeat("a", 43), Method: "S256",
		PublicKey: key(t), Redirect: "http://127.0.0.1:50123/callback", State: strings.Repeat("s", 32)}
}

func TestStartValidate(t *testing.T) {
	if err := good(t).Validate(); err != nil {
		t.Fatal(err)
	}
	noBrowser := good(t)
	noBrowser.Redirect = "" // --no-browser still sends a state
	if err := noBrowser.Validate(); err != nil {
		t.Errorf("--no-browser: %v", err)
	}
	for _, v := range []string{"dev", "1.10.0-rc.1", "0.2.14"} {
		s := good(t)
		s.Version = v
		if err := s.Validate(); err != nil {
			t.Errorf("version %q: %v", v, err)
		}
	}
	for name, change := range map[string]func(*Start){
		"client":         func(s *Start) { s.Client = "curl" },
		"version":        func(s *Start) { s.Version = "1.9.1; rm -rf /" },
		"device control": func(s *Start) { s.Device = "box\x1b[31m" },
		"device long":    func(s *Start) { s.Device = strings.Repeat("d", MaxDevice+1) },
		"method":         func(s *Start) { s.Method = "plain" },
		"challenge":      func(s *Start) { s.Challenge = "short" },
		"key":            func(s *Start) { s.PublicKey = "bm90IGEga2V5" },
		"redirect host":  func(s *Start) { s.Redirect = "http://evil.example:50123/callback" },
		"redirect port":  func(s *Start) { s.Redirect = "http://127.0.0.1:80/callback" },
		"state":          func(s *Start) { s.State = "short" },
		"no state":       func(s *Start) { s.State = "" },
	} {
		s := good(t)
		change(&s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTokenValidate(t *testing.T) {
	ok := Token{Code: strings.Repeat("c", 43), Verifier: strings.Repeat("v", 43)}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Token{{Code: "", Verifier: ok.Verifier}, {Code: ok.Code, Verifier: "short"}, {Code: ok.Code + "!", Verifier: ok.Verifier}} {
		if bad.Validate() == nil {
			t.Errorf("%+v: accepted", bad)
		}
	}
}

func TestDevice(t *testing.T) {
	for in, want := range map[string]string{"box\x1b[31m​ name ": "box [31m name", "  a\t\nb  ": "a b", strings.Repeat("x", 300): strings.Repeat("x", MaxDevice)} {
		got := Device(in)
		if got != want || !validDevice(got) {
			t.Errorf("Device(%q) = %q, want %q", in, got, want)
		}
	}
}
