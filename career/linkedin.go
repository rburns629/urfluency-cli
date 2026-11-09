package career

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// A LinkedIn data export ("Get a copy of your data") is a zip that can also
// hold messages, connections, and contacts. ReadExport opens only Profile.csv
// and Positions.csv, and of Profile.csv keeps only the name, headline, and
// summary: never the address or birth date beside them.
//
// People rename downloads, and macOS unzips them, so the export is accepted
// under any name, as the zip, the folder it unpacks to, or Positions.csv on
// its own. Inside it, the two files are found by name; when one has been
// renamed, by its column names, reading only the first line of each CSV.
//
// The export is data from outside the CLI, so nothing in it is used until it
// passes the checks below: a well-formed zip whose files pass their checksums,
// no links or paths that leave the export, strict CSV with the expected
// columns, UTF-8 text, and fields within LinkedIn's own limits (with room to
// spare). Control and bidirectional-override characters are removed, so text
// shows as what it is. Nothing in the export is ever run.

const (
	// maxCSV bounds how much of each file is read, against a zip that expands
	// into far more than it holds.
	maxCSV = 4 << 20
	// maxEntries bounds how many files an export may list; LinkedIn's largest
	// archive holds a few dozen.
	maxEntries = 10000
	// maxHeader bounds the first line read to recognize a renamed file.
	maxHeader = 4 << 10
	// maxPositions bounds the timeline.
	maxPositions = 500
)

// Field limits, in characters. LinkedIn allows 100 for a title or company,
// 220 for a headline, 2,000 for a description, and 2,600 for an About.
const (
	maxName        = 200
	maxLine        = 300
	maxHeadline    = 500
	maxDescription = 8000
	// maxOfficial matches what the map page accepts for an official title or
	// note, in bytes.
	maxOfficial = 120
)

// Columns each file must have, lowercase. Others are allowed and ignored.
var (
	positionColumns = []string{"company name", "title", "started on"}
	profileColumns  = []string{"first name", "last name"}
)

// ExportSources says which files an import read.
type ExportSources struct {
	Positions string // the file's path inside the export
	Profile   string // "" when the export has none
	// HeadersChecked counts the other files whose first line was read to
	// find a renamed Positions.csv or Profile.csv; nothing else of them is.
	HeadersChecked int
}

// exportFile is one file in an export, zipped or unpacked.
type exportFile struct {
	name      string // slash-separated, relative to the export
	size      int64  // declared size
	encrypted bool
	open      func() (io.ReadCloser, error)
}

// ReadExport reads a LinkedIn export: the zip under any name, the folder it
// unpacks to, or a Positions.csv file.
func ReadExport(exportPath string) (Profile, ExportSources, error) {
	var src ExportSources
	// The path itself is the user's choice, so a link to the export is
	// followed; links inside a folder are not.
	exportPath, err := filepath.EvalSymlinks(exportPath)
	if err != nil {
		return Profile{}, src, fmt.Errorf("open the LinkedIn export: %w", err)
	}
	info, err := os.Stat(exportPath)
	if err != nil {
		return Profile{}, src, fmt.Errorf("open the LinkedIn export: %w", err)
	}
	var files []exportFile
	switch {
	case info.IsDir():
		files, err = folderFiles(exportPath)
	case info.Mode().IsRegular():
		zr, zerr := zip.OpenReader(exportPath)
		switch {
		case zerr == nil:
			defer zr.Close()
			files, err = zipFiles(zr)
		case errors.Is(zerr, zip.ErrFormat):
			files = []exportFile{diskFile(exportPath, filepath.Base(exportPath))}
		default:
			err = zerr
		}
	default:
		err = errors.New("it is neither a file nor a folder")
	}
	if err != nil {
		return Profile{}, src, fmt.Errorf("open the LinkedIn export: %w", err)
	}

	checked := map[string]bool{}
	positions, err := pick(files, "positions.csv", positionColumns, nil, checked)
	if err != nil {
		return Profile{}, src, err
	}
	if positions == nil {
		return Profile{}, src, errors.New("the export has no Positions.csv, which only the larger data archive includes: on LinkedIn, Get a copy of your data › Download larger data archive")
	}
	profile, err := pick(files, "profile.csv", profileColumns, positions, checked)
	if err != nil {
		return Profile{}, src, err
	}
	delete(checked, positions.name)
	if profile != nil {
		delete(checked, profile.name)
	}
	src.Positions, src.HeadersChecked = positions.name, len(checked)

	var p Profile
	if profile != nil {
		src.Profile = profile.name
		rows, err := readCSV(*profile, profileColumns, 1)
		if err != nil {
			return Profile{}, src, fmt.Errorf("read %s: %w", profile.name, err)
		}
		if len(rows) > 0 {
			r := rows[0]
			p.Name = oneLine(r["first name"] + " " + r["last name"])
			p.Headline, p.Summary = oneLine(r["headline"]), strings.TrimSpace(r["summary"])
		}
	}
	rows, err := readCSV(*positions, positionColumns, maxPositions)
	if err != nil {
		return Profile{}, src, fmt.Errorf("read %s: %w", positions.name, err)
	}
	for i, r := range rows {
		start, err := exportMonth(r["started on"])
		if err != nil {
			return Profile{}, src, fmt.Errorf("row %d of %s: start date: %w", i+2, positions.name, err)
		}
		end := ""
		if v := strings.TrimSpace(r["finished on"]); v != "" {
			if end, err = exportMonth(v); err != nil {
				return Profile{}, src, fmt.Errorf("row %d of %s: end date: %w", i+2, positions.name, err)
			}
		}
		p.Positions = append(p.Positions, Position{ID: fmt.Sprintf("r%d", i+1), Title: oneLine(r["title"]),
			Company: oneLine(r["company name"]), Description: strings.TrimSpace(r["description"]), Start: start, End: end})
	}
	if len(p.Positions) == 0 {
		return Profile{}, src, fmt.Errorf("the export's %s lists no positions", positions.name)
	}
	if err := p.Validate(); err != nil {
		return Profile{}, src, fmt.Errorf("the export: %w", err)
	}
	return p, src, nil
}

// zipFiles lists a zip's files, refusing an archive too large to be an export
// or naming a path that leaves it.
func zipFiles(zr *zip.ReadCloser) ([]exportFile, error) {
	if len(zr.File) > maxEntries {
		return nil, fmt.Errorf("the zip lists %d files, more than an export holds", len(zr.File))
	}
	var files []exportFile
	for _, f := range zr.File {
		if !safeName(f.Name) {
			return nil, fmt.Errorf("the zip names an unsafe path, %q", f.Name)
		}
		if f.FileInfo().IsDir() {
			continue
		}
		if !f.Mode().IsRegular() {
			if isCSVName(f.Name) {
				return nil, fmt.Errorf("the zip stores %s as a link, not a file", f.Name)
			}
			continue
		}
		size := int64(f.UncompressedSize64)
		if f.UncompressedSize64 > 1<<62 {
			size = 1 << 62
		}
		files = append(files, exportFile{name: f.Name, size: size, encrypted: f.Flags&0x1 != 0, open: f.Open})
	}
	return files, nil
}

// safeName reports whether a name in a zip stays inside it.
func safeName(name string) bool {
	if name == "" || strings.ContainsAny(name, "\\\x00") || path.IsAbs(name) || filepath.VolumeName(name) != "" {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return false
		}
	}
	return true
}

// folderFiles lists the regular files of an unpacked export, two levels deep.
// Links are never followed, so a link named Positions.csv can't point the
// import at another file.
func folderFiles(root string) ([]exportFile, error) {
	var files []exportFile
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() {
			if rel != "." && strings.Count(filepath.ToSlash(rel), "/") >= 1 {
				return fs.SkipDir
			}
			return nil
		}
		if len(files) >= maxEntries {
			return fmt.Errorf("the folder holds more than %d files, more than an export holds", maxEntries)
		}
		if !d.Type().IsRegular() {
			if isCSVName(d.Name()) {
				return fmt.Errorf("%s is a link or special file, not a file from the export", filepath.ToSlash(rel))
			}
			return nil
		}
		files = append(files, diskFile(p, filepath.ToSlash(rel)))
		return nil
	})
	return files, err
}

// diskFile is a file on disk. Opening it checks that it is still the regular
// file that was listed, not a link put in its place since.
func diskFile(p, name string) exportFile {
	size := int64(-1)
	listed, lerr := os.Lstat(p)
	if lerr == nil {
		size = listed.Size()
	}
	return exportFile{name: name, size: size, open: func() (io.ReadCloser, error) {
		if lerr != nil {
			return nil, lerr
		}
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		opened, err := f.Stat()
		if err != nil || !opened.Mode().IsRegular() || !os.SameFile(listed, opened) {
			f.Close()
			return nil, fmt.Errorf("%s changed while it was being read", name)
		}
		return f, nil
	}}
}

func isCSVName(name string) bool {
	return strings.EqualFold(path.Ext(name), ".csv")
}

// pick finds a file by name or, failing that, by its columns, adding each file
// whose first line it read to checked. It returns an error when more than one
// file fits, so the import never guesses.
func pick(files []exportFile, name string, columns []string, skip *exportFile, checked map[string]bool) (*exportFile, error) {
	var named []*exportFile
	for i := range files {
		if strings.EqualFold(path.Base(files[i].name), name) {
			named = append(named, &files[i])
		}
	}
	if len(named) == 1 {
		return named[0], nil
	}
	if len(named) > 1 {
		return nil, fmt.Errorf("the export holds more than one %s (%s and %s); point the import at one", path.Base(named[0].name), named[0].name, named[1].name)
	}
	var found []*exportFile
	for i := range files {
		f := &files[i]
		if skip != nil && f.name == skip.name {
			continue
		}
		if len(files) > 1 && !isCSVName(f.name) {
			continue
		}
		if f.encrypted || f.size > maxCSV {
			continue
		}
		checked[f.name] = true
		if header, err := firstLine(*f); err == nil && hasColumns(header, columns) {
			found = append(found, f)
		}
	}
	switch len(found) {
	case 0:
		return nil, nil
	case 1:
		return found[0], nil
	}
	return nil, fmt.Errorf("more than one file looks like %s (%s and %s); point the import at one", name, found[0].name, found[1].name)
}

// firstLine reads a CSV file's header row and nothing after it.
func firstLine(f exportFile) ([]string, error) {
	rc, err := f.open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	buf := make([]byte, maxHeader)
	n, err := io.ReadFull(rc, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}
	line, _, _ := bytes.Cut(bytes.TrimPrefix(buf[:n], []byte("\xef\xbb\xbf")), []byte("\n"))
	if !utf8.Valid(line) {
		return nil, errors.New("not UTF-8")
	}
	return csv.NewReader(bytes.NewReader(line)).Read()
}

func hasColumns(header, columns []string) bool {
	have := map[string]bool{}
	for _, h := range header {
		have[strings.ToLower(strings.TrimSpace(h))] = true
	}
	for _, c := range columns {
		if !have[c] {
			return false
		}
	}
	return true
}

// readCSV reads a CSV file into rows keyed by lowercase header, after checking
// its size, encoding, structure, and columns. Values have control characters
// removed.
func readCSV(f exportFile, columns []string, maxRows int) ([]map[string]string, error) {
	if f.encrypted {
		return nil, errors.New("it is encrypted; download the export from LinkedIn again")
	}
	if f.size > maxCSV {
		return nil, fmt.Errorf("it is over %d MB, larger than LinkedIn writes", maxCSV>>20)
	}
	rc, err := f.open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	// Reading to the end lets a zip check the file against its checksum.
	data, err := io.ReadAll(io.LimitReader(rc, maxCSV+1))
	if err != nil {
		return nil, fmt.Errorf("it is damaged (%v); download the export from LinkedIn again", err)
	}
	if len(data) > maxCSV {
		return nil, fmt.Errorf("it is over %d MB, larger than LinkedIn writes", maxCSV>>20)
	}
	if !utf8.Valid(data) {
		return nil, errors.New("it is not UTF-8 text, as LinkedIn writes it; download the export again rather than saving it from a spreadsheet")
	}
	r := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))))
	r.FieldsPerRecord = 0 // every row has the header's number of fields
	header, err := r.Read()
	if errors.Is(err, io.EOF) {
		return nil, errors.New("it is empty")
	}
	if err != nil {
		return nil, fmt.Errorf("it is not a well-formed CSV file: %w", err)
	}
	seen := map[string]bool{}
	for i, h := range header {
		h = strings.ToLower(strings.TrimSpace(h))
		if seen[h] {
			return nil, fmt.Errorf("it has the column %q twice", h)
		}
		seen[h], header[i] = true, h
	}
	var missing []string
	for _, c := range columns {
		if !seen[c] {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("it is missing the columns %s, so it isn't the file LinkedIn writes", strings.Join(missing, ", "))
	}
	var rows []map[string]string
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("it is not a well-formed CSV file: %w", err)
		}
		if len(rows) == maxRows {
			if maxRows == 1 {
				break // Profile.csv: only the first row is used
			}
			return nil, fmt.Errorf("it lists more than %d rows", maxRows)
		}
		row := make(map[string]string, len(header))
		for i, h := range header {
			row[h] = clean(rec[i])
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// clean removes control characters other than newline and tab, and the
// bidirectional embedding, override, and isolate characters that can make text
// display as something other than what it says.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if disallowed(r, true) {
			return -1
		}
		return r
	}, s)
}

func disallowed(r rune, newlines bool) bool {
	switch {
	case r == '\n' || r == '\t':
		return !newlines
	case r < 0x20, r >= 0x7f && r <= 0x9f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}

// oneLine joins a value's lines with spaces and trims it.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

var (
	positionID = regexp.MustCompile(`^r[1-9][0-9]{0,3}$`)
	monthRE    = regexp.MustCompile(`^[0-9]{4}-(0[1-9]|1[0-2])$`)
)

// Validate checks a profile before it is used, whether just imported or read
// back from the career folder: lengths within limits, no control characters,
// unique role IDs, and real months with no role ending before it starts.
func (p Profile) Validate() error {
	if err := text("the name", p.Name, maxName, false); err != nil {
		return err
	}
	if err := text("the headline", p.Headline, maxHeadline, false); err != nil {
		return err
	}
	if err := text("the summary", p.Summary, maxDescription, true); err != nil {
		return err
	}
	if len(p.Positions) == 0 || len(p.Positions) > maxPositions {
		return fmt.Errorf("it needs between 1 and %d positions, not %d", maxPositions, len(p.Positions))
	}
	latest := time.Now().AddDate(1, 0, 0).Format("2006-01")
	ids := map[string]bool{}
	for i, r := range p.Positions {
		at := fmt.Sprintf("position %d", i+1)
		if !positionID.MatchString(r.ID) || ids[r.ID] {
			return fmt.Errorf("%s has an invalid ID", at)
		}
		ids[r.ID] = true
		if strings.TrimSpace(r.Title) == "" {
			return fmt.Errorf("%s has no title", at)
		}
		for _, f := range []struct {
			name, value string
			limit       int
			lines       bool
		}{
			{"title", r.Title, maxLine, false},
			{"company", r.Company, maxLine, false},
			{"description", r.Description, maxDescription, true},
		} {
			if err := text(at+"'s "+f.name, f.value, f.limit, f.lines); err != nil {
				return err
			}
		}
		if len(r.Official) > maxOfficial || len(r.Note) > maxOfficial {
			return fmt.Errorf("%s's official title or note is over %d characters", at, maxOfficial)
		}
		if err := text(at+"'s official title", r.Official, maxOfficial, false); err != nil {
			return err
		}
		if err := text(at+"'s note", r.Note, maxOfficial, false); err != nil {
			return err
		}
		if !monthRE.MatchString(r.Start) || r.Start < "1900-01" || r.Start > latest {
			return fmt.Errorf("%s has an impossible start date, %q", at, r.Start)
		}
		if r.End != "" && (!monthRE.MatchString(r.End) || r.End < r.Start || r.End > latest) {
			return fmt.Errorf("%s has an impossible end date, %q", at, r.End)
		}
	}
	return nil
}

func text(what, s string, limit int, lines bool) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("%s is not UTF-8 text", what)
	}
	if n := utf8.RuneCountInString(s); n > limit {
		return fmt.Errorf("%s is %d characters, over the %d allowed", what, n, limit)
	}
	for _, r := range s {
		if disallowed(r, lines) {
			return fmt.Errorf("%s holds a control character", what)
		}
	}
	return nil
}

// exportMonth reads the export's dates, "Mar 2024" or "2024", as "2024-03"
// (January when only the year is given).
func exportMonth(s string) (string, error) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"Jan 2006", "January 2006", "2006-01", "01/2006", "2006"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.Format("2006-01"), nil
		}
	}
	return "", fmt.Errorf("unreadable date %q", s)
}
