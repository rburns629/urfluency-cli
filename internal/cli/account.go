package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/roburns/urfluency-cli/internal/report"
	"github.com/roburns/urfluency-cli/upload"
)

// Uploading is optional and never part of a scan. `urfluency login` links the
// CLI to an account (login.go) and receives an upload-only token bound to a key
// on this machine (sign.go). `urfluency upload` scans, shows what it will send,
// and asks before sending.

const defaultAPI = "https://api.urfluency.com"

// apiBase is the API to talk to: URFLUENCY_API_URL, or the public API. Plain
// HTTP is allowed only for a local development server.
func apiBase() (string, error) {
	base := os.Getenv("URFLUENCY_API_URL")
	if base == "" {
		return defaultAPI, nil
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("URFLUENCY_API_URL %q is not a URL", base)
	}
	local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return "", fmt.Errorf("URFLUENCY_API_URL must use https, except for localhost")
	}
	return strings.TrimRight(base, "/"), nil
}

var httpClient = &http.Client{Timeout: 30 * time.Second, CheckRedirect: sameOrigin}

// sameOrigin keeps requests that carry the upload or CI token on the origin
// they were sent to. Go forwards Authorization on a redirect to the same host,
// even from https to http, so a redirect that changes the scheme or the host
// is refused.
func sameOrigin(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if first := via[0].URL; req.URL.Scheme != first.Scheme || req.URL.Host != first.Host {
		return fmt.Errorf("refused a redirect from %s://%s to %s://%s", first.Scheme, first.Host, req.URL.Scheme, req.URL.Host)
	}
	return nil
}

// credentials are the upload token `urfluency login` saved. They stay on this
// machine, readable only by the user, and are never printed. KeyStore says
// where the token's key is: "keychain", or "file" with the key in Key. Logins
// from before 1.5.0 have neither, and the API refuses them.
type credentials struct {
	API      string    `json:"api"`
	Token    string    `json:"token"`
	Expires  time.Time `json:"expires_at"`
	KeyStore string    `json:"key_store,omitempty"`
	Key      string    `json:"key,omitempty"`
}

func credentialsPath() (string, error) {
	settings, err := settingsPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(settings), "credentials.json"), nil
}

func loadCredentials() (credentials, error) {
	var c credentials
	path, err := credentialsPath()
	if err != nil {
		return c, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, fmt.Errorf("not logged in; run urfluency login")
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("read credentials: %w", err)
	}
	if time.Now().After(c.Expires) {
		return c, fmt.Errorf("your login expired; run urfluency login")
	}
	return c, nil
}

// save writes the credentials atomically with owner-only permissions.
func (c credentials) save() error {
	path, err := credentialsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".credentials-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// apiError is the API's error body.
type apiError struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

// postJSON sends body as JSON and decodes a JSON response into out when the
// status is 2xx. Otherwise it returns the status and the API's error code.
func postJSON(ctx context.Context, endpoint, token string, body, out any) (int, string, error) {
	return postJSONWith(ctx, endpoint, token, nil, body, out)
}

// postJSONWith is postJSON with extra request headers.
func postJSONWith(ctx context.Context, endpoint, token string, headers map[string]string, body, out any) (int, string, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return 0, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	return sendJSON(req, token, headers, out)
}

// sendJSON sends req and decodes its JSON answer, as postJSON describes.
func sendJSON(req *http.Request, token string, headers map[string]string, out any) (int, string, error) {
	return sendJSONVia(httpClient, req, token, headers, out)
}

// sendJSONVia is sendJSON with another client, such as one that waits longer.
func sendJSONVia(client *http.Client, req *http.Request, token string, headers map[string]string, out any) (int, string, error) {
	endpoint := req.URL.String()
	req.Header.Set("User-Agent", "urfluency/"+Version)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, "", err
	}
	if resp.StatusCode/100 != 2 {
		var e apiError
		if json.Unmarshal(raw, &e) != nil || e.Error == "" {
			e.Error = "unexpected response" // not the API's error format, such as a proxy's page
		}
		return resp.StatusCode, e.Error, nil
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, "", fmt.Errorf("unexpected response from %s: %w", endpoint, err)
		}
	}
	return resp.StatusCode, "", nil
}

func logout(args []string, stdout io.Writer) error {
	if len(args) > 0 {
		return fmt.Errorf("%w: logout takes no arguments", errUsage)
	}
	path, err := credentialsPath()
	if err != nil {
		return err
	}
	// An expired login still has a key to delete; loadCredentials reports the
	// expiry as an error but reads the credentials anyway.
	if c, _ := loadCredentials(); c.KeyStore == "keychain" {
		if err := keys.Delete(c.API); err != nil {
			return fmt.Errorf("delete the login's key from your keychain: %w", err)
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	fmt.Fprintln(stdout, "Logged out. The upload token and its key on this machine were deleted.")
	return nil
}

// signedJSON sends body as JSON (or nothing for a GET) with the credentials'
// token, signed by its key, and decodes a 2xx answer into out, as postJSON
// does.
func signedJSON(ctx context.Context, method, endpoint string, c credentials, body, out any) (int, string, error) {
	return signedJSONVia(ctx, httpClient, method, endpoint, c, body, out)
}

// signedJSONVia is signedJSON with another client.
func signedJSONVia(ctx context.Context, client *http.Client, method, endpoint string, c credentials, body, out any) (int, string, error) {
	key, err := c.privateKey()
	if err != nil {
		return 0, "", err
	}
	var data []byte
	if body != nil {
		if data, err = json.Marshal(body); err != nil {
			return 0, "", err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(data))
	if err != nil {
		return 0, "", err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	signRequest(req, data, c.Token, key)
	return sendJSONVia(client, req, "", nil, out)
}

// loginRefused explains why the API refused a signed request's login.
func loginRefused(code string) error {
	switch code {
	case "cli_update_required":
		return errors.New("this login is from an older urfluency, which the API no longer accepts; run urfluency login")
	case "clock_skew":
		return errors.New("your computer's clock is more than 5 minutes off; correct it and try again")
	}
	return errors.New("the API did not accept your login; run urfluency login")
}

// buildPayload takes only the summary, the combined result, and the facts
// from a report: the parts written for others to read and the counts the
// official model scores, without locations or repository names.
func buildPayload(r report.Report) (upload.Payload, error) {
	if r.Summary == nil || r.Combined == nil || r.Facts == nil {
		return upload.Payload{}, errors.New("the report has no summary to upload")
	}
	facts, err := json.Marshal(r.Facts)
	if err != nil {
		return upload.Payload{}, err
	}
	summary, err := json.Marshal(r.Summary)
	if err != nil {
		return upload.Payload{}, err
	}
	combined, err := json.Marshal(r.Combined)
	if err != nil {
		return upload.Payload{}, err
	}
	tier := upload.SelfReported
	if r.Repos == 0 {
		tier = upload.Declared // nothing in the result came from Git history
	}
	p := upload.Payload{Format: upload.Format, Tool: Version, Report: r.Format, Catalog: r.Catalog, Model: report.ProficiencyModel,
		Tier: tier, Since: r.Since, Summary: summary, Combined: combined, Facts: facts}
	return p, upload.Validate(p)
}

// describePayload says in a few lines what an upload contains.
func describePayload(r report.Report) string {
	counts := map[string]int{}
	for _, rt := range r.Summary.Ratings {
		counts[rt.Area]++
	}
	var b strings.Builder
	fmt.Fprintf(&b, "This upload contains:\n  %s\n", r.Summary.Headline)
	fmt.Fprintf(&b, "  ratings: %s, %s, %s, %s, %s", count(counts["language"], "language"), count(counts["framework"], "framework"),
		count(counts["design"], "design area"), count(counts["tool"], "tool"), count(counts["practice"], "practice"))
	if counts["prompting"] > 0 {
		b.WriteString(", prompting")
	}
	fmt.Fprintf(&b, "\n  %s of strengths, %s holding ratings down, and caveats\n", count(len(r.Summary.Strengths), "line"), count(len(r.Summary.Growth), "line"))
	b.WriteString("  the counts behind them, for urfluency.com's official model: lines, findings per rule, and habits,\n")
	b.WriteString("  per language and for each repository, unnamed\n")
	b.WriteString("It does not contain code, prompt text, repository names, paths, commit hashes, or email addresses.\n")
	b.WriteString("See every field with: urfluency upload --dry-run [same flags]\n")
	return b.String()
}

func count(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

type uploadResult struct {
	ProfileURL string `json:"profile_url"`
	Plan       string `json:"plan"`
}

// pricingURL lists what Pro adds on the site.
const pricingURL = "https://urfluency.com/pricing"

// proNote names what Pro adds to an upload on the site. The CLI's own results
// are the same on every plan.
const proNote = "On Pro, the site adds AI-written persona text, your upload history, and published links: " + pricingURL

func uploadCmd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("upload", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	sf := addScanFlags(fs)
	yes := fs.Bool("yes", false, "")
	dryRun := fs.Bool("dry-run", false, "")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	if err := sf.check(fs); err != nil {
		return err
	}
	path, err := onePath(fs, "upload")
	if err != nil {
		return err
	}
	var creds credentials
	if !*dryRun {
		if creds, err = loadCredentials(); err != nil {
			return err
		}
		if _, err := creds.privateKey(); err != nil {
			return err
		}
	}
	fmt.Fprintln(stderr, "Scanning again: upload builds its own report and does not reuse an earlier scan.")
	r, err := buildReport(ctx, sf, path, false, stderr)
	if err != nil {
		return err
	}
	p, err := buildPayload(r)
	if err != nil {
		return fmt.Errorf("not uploading: %w", err)
	}
	if *dryRun {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(p)
	}
	fmt.Fprint(stdout, describePayload(r))
	if !*yes {
		if !interactive() {
			return fmt.Errorf("%w: confirm with --yes when not running in a terminal", errUsage)
		}
		fmt.Fprint(stdout, "Send it? [y/N] ")
		in := bufio.NewScanner(stdin)
		if !in.Scan() || !strings.EqualFold(strings.TrimSpace(in.Text()), "y") && !strings.EqualFold(strings.TrimSpace(in.Text()), "yes") {
			fmt.Fprintln(stdout, "Nothing was sent.")
			return nil
		}
	}
	var res uploadResult
	status, code, err := signedJSON(ctx, http.MethodPost, creds.API+"/v1/metrics", creds, p, &res)
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	switch {
	case status == http.StatusUnauthorized:
		return loginRefused(code)
	case code == "daily_limit":
		return errors.New("upload: today's upload limit is reached; try again tomorrow (UTC)")
	case status/100 != 2:
		return fmt.Errorf("upload: %s (%d)", code, status)
	}
	fmt.Fprintln(stdout, "Uploaded. Metrics stay private until you publish them.")
	if res.ProfileURL != "" {
		fmt.Fprintln(stdout, "Your profile:", res.ProfileURL)
	}
	if res.Plan != "" && res.Plan != "pro" {
		fmt.Fprintln(stdout, proNote)
	}
	return nil
}

// planNames are the plans as the site names them.
var planNames = map[string]string{"free": "Free", "credit": "Credit packs", "pro": "Pro"}

// status says whether this CLI is logged in, until when, and the account's
// plan. It gates nothing, and the plan is left out when the API is out of reach.
func status(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) > 0 {
		return fmt.Errorf("%w: status takes no arguments", errUsage)
	}
	c, err := loadCredentials()
	if err != nil {
		fmt.Fprintf(stdout, "Not ready to upload: %v. Scans work without an account.\n", err)
		return nil
	}
	fmt.Fprintf(stdout, "Logged in to %s. Uploads are allowed until %s.\n", c.API, c.Expires.Format("2006-01-02"))
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var res struct {
		Plan string `json:"plan"`
	}
	if _, err := c.privateKey(); err != nil {
		fmt.Fprintf(stdout, "Not ready to upload: %v.\n", err)
		return nil
	}
	code, refusal, err := signedJSON(ctx, http.MethodGet, c.API+"/v1/plan", c, nil, &res)
	switch {
	case err != nil:
		fmt.Fprintf(stdout, "Plan: unknown, could not reach %s.\n", c.API)
	case code == http.StatusUnauthorized:
		fmt.Fprintf(stdout, "Not ready to upload: %v.\n", loginRefused(refusal))
	case code/100 != 2 || planNames[res.Plan] == "":
		fmt.Fprintf(stdout, "Plan: unknown (%d).\n", code)
	default:
		fmt.Fprintf(stdout, "Plan: %s.\n", planNames[res.Plan])
		if res.Plan != "pro" {
			fmt.Fprintln(stdout, proNote)
		}
	}
	return nil
}

// deviceName is this machine's name, sent at login so the account's Settings
// can tell connections apart: URFLUENCY_DEVICE_NAME when set, even to empty,
// otherwise the hostname; empty when it cannot be read.
func deviceName() string {
	if name, ok := os.LookupEnv("URFLUENCY_DEVICE_NAME"); ok {
		return strings.TrimSpace(name)
	}
	name, err := os.Hostname()
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(strings.TrimSuffix(name, "."), ".local")
}
