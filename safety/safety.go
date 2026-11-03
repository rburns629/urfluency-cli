// Package safety checks a repository for signs of malicious or privacy-invasive
// behavior before anyone runs it: install-time execution, remote code
// execution, data collection, credential access, obfuscation, persistence,
// supply-chain risks, and committed secrets.
//
// It is static analysis only. Nothing in the repository is executed, and a
// scan can find indicators but never prove a repository is safe; reports say
// so. The same engine runs in `urfluency check` and in the hosted scanner.
package safety

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf16"

	"github.com/rburns629/urfluency-cli/analysis"
	"github.com/rburns629/urfluency-cli/analyzers/secrets"
	"github.com/rburns629/urfluency-cli/rules"
)

// Version identifies the rule set; reports carry it so results can be compared.
const Version = "0.2"

// Severity says how bad a behavior is if it is what it looks like.
type Severity string

const (
	High   Severity = "high"
	Medium Severity = "medium"
	Low    Severity = "low"
)

// Confidence says how likely a match is to be the behavior it names.
type Confidence string

const (
	Likely   Confidence = "high"
	Possible Confidence = "medium"
	Weak     Confidence = "low"
)

// Verdicts. A report never says "safe".
const (
	NoIndicators      = "No indicators found"
	ReviewRecommended = "Review recommended"
	HighRisk          = "High-risk indicators"
)

// Categories, in report order.
var Categories = []struct{ ID, Title string }{
	{"install", "Install-time execution"},
	{"remote-code", "Remote code execution"},
	{"data-collection", "Data collection"},
	{"credentials", "Credential access"},
	{"obfuscation", "Obfuscation"},
	{"persistence", "Persistence and abuse"},
	{"supply-chain", "Supply chain"},
	{"secrets", "Secrets"},
}

// Finding is one indicator.
type Finding struct {
	Rule       string     `json:"rule"`
	Category   string     `json:"category"`
	Title      string     `json:"title"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	Path       string     `json:"path"`
	Line       int        `json:"line,omitempty"`
	// Evidence is a short excerpt of the matched line. Secret findings never
	// carry evidence, so values are not reproduced.
	Evidence string `json:"evidence,omitempty"`
	Why      string `json:"why"`
}

// Report is the result of a scan.
type Report struct {
	Version string `json:"version"`
	Verdict string `json:"verdict"`
	Score   int    `json:"score"` // 0–100; 100 means nothing was found
	Files   int    `json:"files_checked"`
	Skipped int    `json:"files_skipped"`
	// Unread names up to maxUnread of the skipped files outside tests, which
	// keep a scan from saying nothing was found, so their owner can act.
	Unread    []string  `json:"unread,omitempty"`
	Truncated bool      `json:"truncated,omitempty"` // the file limit was reached
	Findings  []Finding `json:"findings"`
	Counts    []Count   `json:"by_category"`
	Caveat    string    `json:"caveat"`
}

// Count is the number of findings in one category.
type Count struct {
	Category string `json:"category"`
	Title    string `json:"title"`
	Findings int    `json:"findings"`
}

// Limits bound a scan so a hostile repository cannot exhaust it.
type Limits struct {
	MaxFiles    int   // files read
	MaxFileSize int64 // bytes per file; larger files are skipped (binaries are still identified)
}

// DefaultLimits suit a typical repository.
// maxUnread bounds the unread files a report names.
const maxUnread = 20

var DefaultLimits = Limits{MaxFiles: 20000, MaxFileSize: 2 << 20}

// skipDirs are never read: version control metadata and installed
// dependencies, which are not the repository's own code. Committed
// dependencies under other names are still read.
var skipDirs = map[string]bool{".git": true, "node_modules": true, ".venv": true, "venv": true, "__pycache__": true}

// dependencyDirs are the skipDirs that hold installed packages. Files Git
// tracks in them were committed with the repository, and Node loads a
// committed node_modules, so those are read, softened one level.
var dependencyDirs = map[string]bool{"node_modules": true, ".venv": true, "venv": true}

// committedDependencies returns the files Git tracks in dependency folders under
// dir, and the folders that hold them. Outside a Git repository there are none.
func committedDependencies(ctx context.Context, dir string) (files, dirs map[string]bool) {
	files, dirs = map[string]bool{}, map[string]bool{}
	var specs []string
	for d := range dependencyDirs {
		specs = append(specs, ":(glob)**/"+d+"/**")
	}
	out, err := git(ctx, dir, append([]string{"ls-files", "-z", "--"}, specs...)...)
	if err != nil {
		return files, dirs
	}
	for p := range strings.SplitSeq(string(out), "\x00") {
		if p == "" {
			continue
		}
		files[p] = true
		for i := range len(p) {
			if p[i] == '/' {
				dirs[p[:i]] = true
			}
		}
	}
	return files, dirs
}

// inDependency reports whether rel is inside a dependency folder.
func inDependency(rel string) bool {
	return slices.ContainsFunc(strings.Split(path.Dir(rel), "/"), func(s string) bool { return dependencyDirs[s] })
}

// Scan checks the files under dir.
func Scan(ctx context.Context, dir string, limits Limits) (Report, error) {
	r := Report{Version: Version, Findings: []Finding{}, Caveat: "A scan finds indicators of risky behavior. It cannot prove a repository is safe."}
	// Paths are listed first and read in order of what runs on install, so
	// padding the repository with files cannot push its manifests past the
	// file limit. Listing stops at ten times the limit.
	type entry struct {
		path, rel string
		size      int64
	}
	var entries []entry
	committed, committedDirs := committedDependencies(ctx, dir)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == dir {
				return err // a missing or unreadable folder is not a clean one
			}
			return nil // unreadable entries are skipped
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if skipDirs[d.Name()] && path != dir && !committedDirs[rel] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // symlinks and devices are never followed
		}
		if inDependency(rel) && !committed[rel] {
			return nil // installed, not committed
		}
		if len(entries) >= 10*limits.MaxFiles {
			r.Truncated = true
			return filepath.SkipAll
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		entries = append(entries, entry{path, rel, info.Size()})
		return nil
	})
	if err != nil && !errors.Is(err, filepath.SkipAll) {
		return Report{}, err
	}
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i].rel, entries[j].rel
		if inDependency(a) != inDependency(b) {
			return !inDependency(a) // the repository's own files first
		}
		if installFile(a) != installFile(b) {
			return installFile(a)
		}
		if da, db := strings.Count(a, "/"), strings.Count(b, "/"); da != db {
			return da < db
		}
		return a < b
	})
	var files []analysis.File
	// unread counts the skipped files outside tests and fixtures, which make
	// the scan incomplete; a test's oversized fixture runs nothing.
	unread := 0
	for _, e := range entries {
		if len(files)+r.Skipped >= limits.MaxFiles {
			r.Truncated = true
			break
		}
		content, err := readBounded(e.path, e.rel, e.size, limits.MaxFileSize)
		if err != nil {
			r.Skipped++
			if where, ok := buildOnly(e.rel); !ok || where != "tests" {
				unread++
				if len(r.Unread) < maxUnread {
					r.Unread = append(r.Unread, e.rel)
				}
			}
			continue
		}
		if !isExecutable(content) && textual(e.rel, content) {
			content = decodeText(content)
		}
		files = append(files, analysis.File{Path: e.rel, Content: content})
	}
	r.Files = len(files)

	perFile := make([][]Finding, len(files))
	parallel(len(files), func(i int) { perFile[i] = checkFile(files[i]) })
	for _, found := range perFile {
		r.Findings = append(r.Findings, found...)
	}
	r.Findings = append(r.Findings, checkRepository(files)...)
	sec, err := secretFindings(ctx, files)
	if err != nil {
		return Report{}, err
	}
	r.Findings = append(r.Findings, sec...)
	for i := range r.Findings {
		r.Findings[i] = softenDependency(softenOutsideRuntime(r.Findings[i]))
	}

	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if rank(a.Severity) != rank(b.Severity) {
			return rank(a.Severity) > rank(b.Severity)
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Line < b.Line
	})
	r.Verdict, r.Score = judge(r.Findings)
	// What was not read could hold anything, so an incomplete scan never says
	// nothing was found, unless all it skipped were tests' files.
	if r.Truncated || r.Skipped > 0 {
		if r.Verdict == NoIndicators && (r.Truncated || unread > 0) {
			r.Verdict = ReviewRecommended
		}
		var why []string
		if r.Skipped > 0 {
			why = append(why, fmt.Sprintf("%d files were over the size limit or unreadable", r.Skipped))
		}
		if r.Skipped > unread {
			why = append(why, fmt.Sprintf("%d of them in tests", r.Skipped-unread))
		}
		if r.Truncated {
			why = append(why, fmt.Sprintf("the scan stopped at %d files", limits.MaxFiles))
		}
		r.Caveat += " Not every file was checked: " + strings.Join(why, ", and ") + "."
	}
	counts := map[string]int{}
	for _, f := range r.Findings {
		counts[f.Category]++
	}
	for _, c := range Categories {
		r.Counts = append(r.Counts, Count{Category: c.ID, Title: c.Title, Findings: counts[c.ID]})
	}
	return r, nil
}

// readBounded reads a file, or only its first bytes when it is over the limit:
// enough to recognize an executable, and all that is needed of a large image,
// archive, or other file that does not run. A large script, manifest, or
// source file is an error, so the scan counts it as skipped.
func readBounded(path, rel string, size, limit int64) ([]byte, error) {
	if size <= limit {
		return os.ReadFile(path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	head := make([]byte, 4096)
	n, _ := f.Read(head)
	if isExecutable(head[:n]) || !textual(rel, head[:n]) {
		return head[:n], nil
	}
	return nil, fmt.Errorf("%s: over %d bytes", path, limit)
}

// installFile reports manifests, build scripts, and workflows: what runs when a
// project is installed or built, read before anything else.
func installFile(rel string) bool {
	switch path.Base(rel) {
	case "package.json", "setup.py", "setup.cfg", "pyproject.toml", "requirements.txt", "composer.json", "Gemfile",
		"binding.gyp", "Makefile", "build.rs", "Cargo.toml":
		return true
	}
	return strings.HasSuffix(rel, ".gemspec") || strings.HasPrefix(rel, ".github/workflows/")
}

// buildOnly reports files that run in tests, CI, or container builds rather
// than on the machine of someone installing or running the project.
func buildOnly(p string) (string, bool) {
	base := path.Base(p)
	switch {
	case analysis.IsTestPath(p) || inDir(p, "testdata", "fixtures", "fixture", "_fixture", "_fixtures", "__fixtures__", "__mocks__", "e2e", "integration"):
		return "tests", true
	case inDir(p, "examples", "example", "demo", "demos", "samples", "sample", "docs_src"):
		return "example code", true
	case strings.HasPrefix(p, ".github/workflows/") || base == ".gitlab-ci.yml" || strings.HasPrefix(p, ".circleci/") || base == "azure-pipelines.yml":
		return "CI", true
	case base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") || strings.HasSuffix(base, ".dockerfile") || composeFile(base):
		return "container builds", true
	}
	return "", false
}

// composeFile reports a Docker Compose file, which starts containers, often
// a local database with a development password, rather than running on
// install.
func composeFile(base string) bool {
	switch base {
	case "compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml":
		return true
	}
	return strings.HasPrefix(base, "docker-compose.") && (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml"))
}

// inDir reports whether a path is inside a directory with one of the names,
// at any depth.
func inDir(p string, names ...string) bool {
	for _, n := range names {
		if strings.Contains("/"+p, "/"+n+"/") {
			return true
		}
	}
	return false
}

// softenOutsideRuntime lowers a finding that does not run when someone
// installs or uses the project. In tests and example code it becomes a note:
// listed, but not changing the verdict, since scanners' and parsers' tests
// hold attack strings as data and examples hold demo credentials; an install
// hook that runs such a file is reported on its own. In CI and container
// builds it drops one severity, to low confidence.
func softenOutsideRuntime(f Finding) Finding {
	where, ok := buildOnly(f.Path)
	if !ok || f.Rule == "safety.executable" {
		return f
	}
	if where == "tests" || where == "example code" {
		f.Severity, f.Confidence = Low, Weak
		f.Why = "In " + where + ", which run only when someone runs them, not on install; " + strings.ToLower(f.Why[:1]) + f.Why[1:]
		return f
	}
	switch f.Severity {
	case High:
		f.Severity = Medium
	case Medium:
		f.Severity = Low
	}
	f.Confidence = Weak
	f.Why = "In " + where + ", which do not run on install; " + strings.ToLower(f.Why[:1]) + f.Why[1:]
	return f
}

// softenDependency lowers a finding in a committed dependency folder by one
// severity: the code is someone else's package, but it is loaded when the
// project runs.
func softenDependency(f Finding) Finding {
	if !inDependency(f.Path) {
		return f
	}
	switch f.Severity {
	case High:
		f.Severity = Medium
	case Medium:
		f.Severity = Low
	}
	f.Why = "In a committed dependency folder; " + strings.ToLower(f.Why[:1]) + f.Why[1:]
	return f
}

func rank(s Severity) int {
	switch s {
	case High:
		return 3
	case Medium:
		return 2
	}
	return 1
}

func weight(c Confidence) float64 {
	switch c {
	case Likely:
		return 1
	case Possible:
		return 0.6
	}
	return 0.3
}

// note reports a finding too minor to change the verdict: low severity with
// low confidence. Notes are still listed.
func note(f Finding) bool { return f.Severity == Low && f.Confidence == Weak }

// judge turns findings into a verdict and a 0–100 score. Any likely or
// possible high-severity finding is high risk; any other finding that is not
// a note means review. The score falls with each finding by severity and
// confidence; a rule counts at most three times, and notes cost at most ten
// points in all, so a large project with many harmless notes stays high.
func judge(findings []Finding) (string, int) {
	penalty := map[Severity]float64{High: 35, Medium: 12, Low: 4}
	perRule := map[string]int{}
	total, notes := 0.0, 0.0
	verdict := NoIndicators
	for _, f := range findings {
		switch {
		case f.Severity == High && f.Confidence != Weak:
			verdict = HighRisk
		case !note(f) && verdict == NoIndicators:
			verdict = ReviewRecommended
		}
		if perRule[f.Rule] < 3 {
			perRule[f.Rule]++
			if note(f) {
				notes += penalty[f.Severity] * weight(f.Confidence)
			} else {
				total += penalty[f.Severity] * weight(f.Confidence)
			}
		}
	}
	total += math.Min(notes, 10)
	score := int(math.Round(math.Max(0, 100-total)))
	if verdict == HighRisk {
		score = min(score, 40)
	}
	return verdict, score
}

// secretFindings reuses the CLI's credential scanner; values are never kept.
func secretFindings(ctx context.Context, files []analysis.File) ([]Finding, error) {
	sc := secrets.Scanner{}
	var candidates []analysis.File
	for _, f := range files {
		if sc.Applies(f.Path) && !isBinary(f.Content) {
			candidates = append(candidates, f)
		}
	}
	// One file per call, in parallel; the results keep the files' order.
	perFile := make([][]analysis.Finding, len(candidates))
	errs := make([]error, len(candidates))
	parallel(len(candidates), func(i int) {
		perFile[i], errs[i] = sc.Analyze(ctx, candidates[i:i+1])
	})
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	var out []Finding
	for _, f := range slices.Concat(perFile...) {
		title := "Committed secret"
		why := "A credential committed to a public repository can be used by anyone who finds it."
		if rule, ok := rules.Lookup(f.Rule); ok {
			title, why = rule.Title, rule.Why
		}
		sev, conf := Medium, Possible
		if isDoc(f.Path) {
			// Documentation shows example credentials far more often than real ones.
			sev, conf = Low, Weak
		}
		out = append(out, Finding{Rule: f.Rule, Category: "secrets", Title: title, Severity: sev, Confidence: conf, Path: f.Path, Line: f.Line, Why: why})
	}
	return out, nil
}

func isBinary(b []byte) bool {
	head := b
	if len(head) > 8000 {
		head = head[:8000]
	}
	return bytes.IndexByte(head, 0) >= 0
}

// textual reports files that hold code, scripts, or configuration. They are
// read as text even with NUL bytes or in UTF-16, which would otherwise make a
// script look binary and hide it from every rule.
func textual(p string, content []byte) bool {
	if markers, block := lineCommentMarkers(p); len(markers) > 0 || block || isScript(p) || isDoc(p) {
		return true
	}
	switch ext(p) {
	case ".json", ".xml", ".html", ".htm", ".vbs", ".psd1", ".gyp":
		return true
	}
	return bytes.HasPrefix(content, []byte("#!"))
}

// decodeText returns content as UTF-8 text with the same lines: a UTF-8 byte
// order mark removed, UTF-16 decoded, and any other NUL bytes dropped.
func decodeText(b []byte) []byte {
	b = bytes.TrimPrefix(b, []byte("\xEF\xBB\xBF"))
	switch {
	case bytes.HasPrefix(b, []byte("\xFF\xFE")):
		return utf16Text(b[2:], binary.LittleEndian)
	case bytes.HasPrefix(b, []byte("\xFE\xFF")):
		return utf16Text(b[2:], binary.BigEndian)
	case bytes.IndexByte(b, 0) < 0:
		return b
	case zeroShare(b, 1) > 0.9:
		return utf16Text(b, binary.LittleEndian) // ASCII in UTF-16 without a mark
	case zeroShare(b, 0) > 0.9:
		return utf16Text(b, binary.BigEndian)
	}
	return bytes.ReplaceAll(b, []byte{0}, nil)
}

// zeroShare is the share of NUL bytes at even (0) or odd (1) offsets in the
// first kilobyte.
func zeroShare(b []byte, odd int) float64 {
	b = b[:min(len(b), 1024)]
	zeros, n := 0, 0
	for i := odd; i < len(b); i += 2 {
		n++
		if b[i] == 0 {
			zeros++
		}
	}
	if n == 0 {
		return 0
	}
	return float64(zeros) / float64(n)
}

func utf16Text(b []byte, order binary.ByteOrder) []byte {
	units := make([]uint16, len(b)/2)
	for i := range units {
		units[i] = order.Uint16(b[2*i:])
	}
	return []byte(string(utf16.Decode(units)))
}

// isExecutable recognizes ELF, Mach-O, and Windows PE files.
func isExecutable(b []byte) bool {
	switch {
	case bytes.HasPrefix(b, []byte("\x7fELF")):
		return true
	case bytes.HasPrefix(b, []byte("MZ")) && len(b) > 64:
		return true
	case len(b) >= 4:
		m := string(b[:4])
		return m == "\xfe\xed\xfa\xce" || m == "\xfe\xed\xfa\xcf" || m == "\xce\xfa\xed\xfe" || m == "\xcf\xfa\xed\xfe" || m == "\xca\xfe\xba\xbe"
	}
	return false
}

func excerpt(line string) string {
	line = strings.TrimSpace(line)
	if r := []rune(line); len(r) > 140 {
		return string(r[:140]) + "…"
	}
	return line
}

// parallel calls fn(i) for each i in [0, n) on every core Go uses.
func parallel(n int, fn func(i int)) {
	var next atomic.Int64
	var wg sync.WaitGroup
	for range min(runtime.GOMAXPROCS(0), n) {
		wg.Go(func() {
			for i := int(next.Add(1)) - 1; i < n; i = int(next.Add(1)) - 1 {
				fn(i)
			}
		})
	}
	wg.Wait()
}
