package cli

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	loginbody "github.com/roburns/urfluency-cli/login"
)

// `urfluency login` signs in like gcloud: it opens the website, the user
// approves there (entering a code urfluency.com emails them), and the website
// hands a one-time code back to a listener on 127.0.0.1 that only this
// process runs (RFC 8252). The code is traded, with a PKCE verifier (RFC
// 7636) only this process knows, for an upload token bound to a key made for
// this login. A phishing link is useless: its code would go to the victim's
// own machine, and without the verifier and key it buys nothing.
//
// With --no-browser, for machines without one, the website shows the code
// instead, and the user pastes it here.

// loginStart is the API's answer to starting a login.
type loginStart struct {
	RequestID    string `json:"request_id"`
	AuthorizeURL string `json:"authorize_url"`
	ExpiresIn    int    `json:"expires_in"`
}

type loginToken struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// openBrowser opens a web page; tests replace it with a fake browser.
var openBrowser = func(link string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", link)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", link)
	default:
		cmd = exec.Command("xdg-open", link)
	}
	return cmd.Start()
}

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func login(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	noBrowser := fs.Bool("no-browser", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return fmt.Errorf("%w: login takes only --no-browser", errUsage)
	}
	if *noBrowser && !interactive() {
		return fmt.Errorf("%w: login --no-browser needs a terminal to paste the code into", errUsage)
	}
	base, err := apiBase()
	if err != nil {
		return err
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	verifier, state := randomString(32), randomString(24)
	sum := sha256.Sum256([]byte(verifier))

	var codes <-chan string
	redirect := ""
	if !*noBrowser {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("listen for the browser: %w; try urfluency login --no-browser", err)
		}
		redirect = fmt.Sprintf("http://127.0.0.1:%d/callback", ln.Addr().(*net.TCPAddr).Port)
		var stop func()
		codes, stop = serveCallback(ln, state)
		defer stop()
	}

	device := loginbody.Device(deviceName())
	var start loginStart
	status, code, err := postJSON(ctx, base+"/v1/auth/cli", "", loginbody.Start{Client: loginbody.Client, Version: Version, Device: device,
		Challenge: base64.RawURLEncoding.EncodeToString(sum[:]), Method: "S256",
		PublicKey: base64.RawURLEncoding.EncodeToString(pub), Redirect: redirect, State: state}, &start)
	if err != nil {
		return fmt.Errorf("start login: %w", err)
	}
	if status/100 != 2 {
		return fmt.Errorf("start login: %s (%d)", code, status)
	}
	if start.ExpiresIn <= 0 || start.RequestID == "" {
		return errors.New("start login: the server sent no login request or expiry; try again later")
	}
	if err := checkLink(start.AuthorizeURL, base); err != nil {
		return fmt.Errorf("start login: %w", err)
	}
	if device != "" {
		fmt.Fprintf(stdout, "Settings will list this machine as %q; set URFLUENCY_DEVICE_NAME to rename it, or to \"\" to send no name.\n\n", device)
	}

	ctx, cancel := context.WithTimeout(ctx, time.Duration(start.ExpiresIn)*time.Second)
	defer cancel()
	var authCode string
	if *noBrowser {
		fmt.Fprintf(stdout, "Open this link on any device, sign in, and approve the login:\n  %s\n\nThen paste the code the page shows: ", start.AuthorizeURL)
		if authCode, err = readCode(ctx); err != nil {
			return err
		}
	} else {
		if openBrowser(start.AuthorizeURL) != nil {
			fmt.Fprintf(stdout, "Open this link in your browser, sign in, and approve the login:\n  %s\n\n", start.AuthorizeURL)
		} else {
			fmt.Fprintf(stdout, "Your browser is opening urfluency.com to approve this login. If it does not, open:\n  %s\n\n", start.AuthorizeURL)
		}
		fmt.Fprintln(stdout, "Waiting for approval… (on a machine without a browser, use urfluency login --no-browser)")
		select {
		case authCode = <-codes:
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return errors.New("the login was not approved in time; run urfluency login again")
			}
			return ctx.Err()
		}
	}

	var tok loginToken
	exchange := loginbody.Token{Code: authCode, Verifier: verifier}
	if exchange.Validate() != nil {
		return errors.New("that is not the login code the browser showed; run urfluency login again and copy it exactly")
	}
	status, code, err = postJSON(ctx, base+"/v1/auth/cli/"+url.PathEscape(start.RequestID)+"/token", "", exchange, &tok)
	switch {
	case err != nil:
		return fmt.Errorf("finish login: %w", err)
	case code == "invalid_grant":
		return errors.New("the login code was wrong or expired; run urfluency login again")
	case status/100 != 2:
		return fmt.Errorf("finish login: %s (%d)", code, status)
	case tok.AccessToken == "" || tok.ExpiresIn <= 0:
		return errors.New("finish login: the server sent no token or expiry; try again later")
	}
	c := credentials{API: base, Token: tok.AccessToken, Expires: time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)}
	if err := c.saveKey(key.Seed()); err != nil {
		return fmt.Errorf("save login: %w", err)
	}
	if err := c.save(); err != nil {
		return fmt.Errorf("save login: %w", err)
	}
	if c.KeyStore == "file" {
		fmt.Fprintln(stdout, "No system keychain was available, so this login's key is kept in credentials.json, readable only by you.")
	}
	fmt.Fprintf(stdout, "Logged in. Uploads are allowed until %s; run urfluency upload when you want to share results.\n", c.Expires.Format("2006-01-02"))
	return nil
}

// checkLink makes sure the page to open is the website, over https, and not
// anything a browser opener would treat differently, such as a file.
func checkLink(link, api string) error {
	u, err := url.Parse(link)
	if err != nil || u.Host == "" {
		return fmt.Errorf("the server sent no approval link")
	}
	local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"
	if u.Scheme != "https" && !(u.Scheme == "http" && local && strings.HasPrefix(api, "http://")) {
		return fmt.Errorf("refusing to open %q: approval links use https", link)
	}
	return nil
}

// readCode reads the pasted authorization code.
func readCode(ctx context.Context) (string, error) {
	line := make(chan string, 1)
	go func() {
		in := bufio.NewScanner(stdin)
		if in.Scan() {
			line <- strings.TrimSpace(in.Text())
		}
		close(line)
	}()
	select {
	case s, ok := <-line:
		if !ok || s == "" {
			return "", errors.New("no code was pasted; run urfluency login again")
		}
		return s, nil
	case <-ctx.Done():
		return "", errors.New("the login was not approved in time; run urfluency login again")
	}
}

// serveCallback answers the browser's one redirect on ln: a request with the
// login's state delivers its code. Anything else, such as another local
// program guessing the port, is refused without a code.
func serveCallback(ln net.Listener, state string) (<-chan string, func()) {
	codes := make(chan string, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := q.Get("code")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 || code == "" {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, callbackPage("This page did not come from your login. Run urfluency login again."))
			return
		}
		select {
		case codes <- code:
			io.WriteString(w, callbackPage("Logged in. You can close this tab and return to your terminal."))
		default:
			io.WriteString(w, callbackPage("This login is already finished. You can close this tab."))
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln)
	return codes, func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}
}

func callbackPage(message string) string {
	return `<!doctype html><meta charset="utf-8"><title>urfluency login</title>` +
		`<body style="font:16px system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem"><p><strong>urfluency</strong></p><p>` + message + `</p></body>`
}

// saveKey keeps the login's key in the system keychain, or, when there is
// none, in the credentials themselves; c records which.
func (c *credentials) saveKey(seed []byte) error {
	if useKeychain() {
		if err := keys.Set(c.API, seed); err == nil {
			c.KeyStore = "keychain"
			return nil
		}
	}
	c.KeyStore, c.Key = "file", base64.RawURLEncoding.EncodeToString(seed)
	return nil
}
