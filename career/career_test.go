package career

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	names := map[string]string{"Atlas": "NAME1", "Atlas API": "NAME2"}
	for _, tc := range []struct{ in, want string }{
		{"Fix login for jane.doe@example.com", "Fix login for [removed]"},
		{"See https://wiki.corp.example/x?y=1 for details", "See [removed] for details"},
		{"Point build at git@github.com:acme/app.git", "Point build at [removed]"},
		{"Route traffic to 10.20.30.40:8443", "Route traffic to [host]"},
		{"Move api.cloud.internal behind the proxy", "Move [host] behind the proxy"},
		{"Close PLAT-1234 and OPS-9", "Close [ticket] and [ticket]"},
		{"Hash with SHA-256 and read UTF-8", "Hash with SHA-256 and read UTF-8"},
		{"Grant roles in acme-prod-482913", "Grant roles in [removed]"},
		{"Bill account 123456789012", "Bill account [removed]"},
		{"Use subscription 0b7c1f6e-1a2b-4c3d-8e9f-0123456789ab", "Use subscription [removed]"},
		{"Rotate ghp_abcdefghijklmnopqrstuvwxyz0123456789", "Rotate [removed]"},
		{"Revert 3f9a2b7c1d4e5f60718293a4b5c6d7e8f9012345", "Revert [removed]"},
		{"Read /Users/jane/work/secret.txt today", "Read [removed] today"},
		{"Add the Atlas API client and an Atlas page", "Add the NAME2 client and an NAME1 page"},
		{"Port the portal to ASP.NET and Socket.IO", "Port the portal to ASP.NET and Socket.IO"},
		{"Add a facade for the decoder", "Add a facade for the decoder"},
	} {
		if got := Redact(tc.in, names); got != tc.want {
			t.Errorf("Redact(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A replacement that contains its own name, as a generic description often
// does, is put in once and not matched again.
func TestRedactReplacementHoldingTheName(t *testing.T) {
	names := map[string]string{"Billing": "the billing service", "System": "an internal system", "Atlas": "Atlas"}
	got := Redact("Fix Billing retries in System and Atlas", names)
	if want := "Fix the billing service retries in an internal system and Atlas"; got != want {
		t.Errorf("Redact = %q, want %q", got, want)
	}
}

func validPack() Pack {
	return Pack{Format: Format, Kind: LinkedIn,
		Roles:    []PackRole{{ID: "r1", Title: "Software Engineer", Company: "Example Co", Start: "2021-03"}},
		Features: []PackFeature{{ID: "f1", RoleID: "r1", Summary: "Built the provisioning API", Commits: 12, Share: 80, Start: "2021-04", End: "2022-01"}},
		Facts:    []PackFact{{ID: "q1", Kind: FactScale, RoleID: "r1", Text: "about 6,000 cloud accounts"}},
		Skills:   []string{"Go", "Terraform"}}
}

func TestValidatePack(t *testing.T) {
	if err := ValidatePack(validPack()); err != nil {
		t.Fatalf("valid pack refused: %v", err)
	}
	for name, change := range map[string]func(*Pack){
		"email":        func(p *Pack) { p.Facts[0].Text = "ask jane@example.com" },
		"url":          func(p *Pack) { p.Features[0].Summary = "see https://example.com" },
		"path":         func(p *Pack) { p.Features[0].Summary = "in /home/jane/app" },
		"unknown role": func(p *Pack) { p.Features[0].RoleID = "r9" },
		"bad month":    func(p *Pack) { p.Roles[0].Start = "March 2021" },
		"kind":         func(p *Pack) { p.Kind = "cv" },
		"long":         func(p *Pack) { p.Features[0].Summary = strings.Repeat("a", 401) },
		"no evidence":  func(p *Pack) { p.Features, p.Facts = nil, nil },
	} {
		p := validPack()
		change(&p)
		if err := ValidatePack(p); err == nil {
			t.Errorf("%s: pack accepted", name)
		}
	}
	p := validPack()
	p.Facts[0].Text = "ask jane@example.com"
	if err := ValidatePack(p); !errors.Is(err, ErrIdentifying) {
		t.Errorf("email: got %v, want ErrIdentifying", err)
	}
}

func TestRedactedPackValidates(t *testing.T) {
	p := validPack()
	p.Features[0].Summary = "Moved Atlas to https://atlas.corp.example and fixed PLAT-12 for jane@example.com"
	RedactPack(&p, ForPack([]Name{{Token: "NAME1", Found: "Atlas", Generic: "an internal developer portal"}}))
	if err := ValidatePack(p); err != nil {
		t.Fatalf("redacted pack refused: %v (%q)", err, p.Features[0].Summary)
	}
	if strings.Contains(p.Features[0].Summary, "Atlas") {
		t.Errorf("name kept: %q", p.Features[0].Summary)
	}
}

func TestValidateAssistRefusesRawNames(t *testing.T) {
	a := AssistRequest{Format: Format, Names: []AssistName{{Token: "Atlas", Context: "the portal"}}}
	if err := ValidateAssist(a); err == nil {
		t.Error("a name that is not a token was accepted")
	}
	a.Names[0].Token = "NAME1"
	if err := ValidateAssist(a); err != nil {
		t.Errorf("token refused: %v", err)
	}
}

func TestReadExport(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "export.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	write := func(name, body string) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	write("Profile.csv", "\ufeffFirst Name,Last Name,Address,Birth Date,Headline,Summary\nJane,Doe,1 Main St,Jan 1 1990,Engineer,I build platforms.\n")
	write("Positions.csv", "Company Name,Title,Description,Location,Started On,Finished On\n"+
		"Example Co,Senior Engineer,\"Builds the platform, end to end.\",Remote,Mar 2024,\n"+
		"Example Co,Engineer,,Remote,2021,Feb 2024\n")
	write("messages.csv", "FROM,TO,CONTENT\na,b,private\n")
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	p, src, err := ReadExport(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	if src.Positions != "Positions.csv" || src.Profile != "Profile.csv" || src.HeadersChecked != 0 {
		t.Errorf("sources = %+v", src)
	}
	if p.Name != "Jane Doe" || p.Headline != "Engineer" || len(p.Positions) != 2 {
		t.Fatalf("profile = %+v", p)
	}
	if got := p.Positions[0]; got.ID != "r1" || got.Start != "2024-03" || got.End != "" || got.Description != "Builds the platform, end to end." {
		t.Errorf("first position = %+v", got)
	}
	if got := p.Positions[1]; got.Start != "2021-01" || got.End != "2024-02" {
		t.Errorf("second position = %+v", got)
	}
	if strings.Contains(strings.Join([]string{p.Name, p.Headline, p.Summary}, " "), "Main St") {
		t.Error("the address was read")
	}
}

func TestWithRepositories(t *testing.T) {
	ev := Evidence{Repos: []RepoEvidence{{Name: "cp-orbit-ns-deploy"}, {Name: "returns"}, {Name: "portalV2"}}}
	names := WithRepositories(map[string]string{}, ev)
	if names["cp-orbit-ns-deploy"] != "the project" || names["portalV2"] != "the project" || names["returns"] != "" {
		t.Errorf("names = %v", names)
	}
	if got := Redact("Deploy cp-orbit-ns-deploy and the returns job", names); got != "Deploy the project and the returns job" {
		t.Errorf("Redact = %q", got)
	}
}

const testPositions = "Company Name,Title,Description,Location,Started On,Finished On\n" +
	"Example Co,Senior Engineer,Builds the platform.,Remote,Mar 2024,\n"

// writeZip writes name/body pairs, in order, to a zip under dir.
func writeZip(t *testing.T, dir, zipName string, files ...string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < len(files); i += 2 {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: files[i], Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(files[i+1]))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, zipName)
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// People rename the download, macOS unzips it, and some send only the CSV.
func TestReadExportAcceptsAnyName(t *testing.T) {
	dir := t.TempDir()
	zipped := writeZip(t, dir, "my linkedin (1).zip.zip", "Basic_LinkedInDataExport/Positions.csv", testPositions)

	folder := filepath.Join(dir, "unzipped")
	os.MkdirAll(filepath.Join(folder, "nested"), 0o700)
	os.WriteFile(filepath.Join(folder, "Positions.csv"), []byte(testPositions), 0o600)
	os.WriteFile(filepath.Join(folder, "messages.csv"), []byte("FROM,TO,CONTENT\na,b,private\n"), 0o600)

	lone := filepath.Join(dir, "my jobs.txt")
	os.WriteFile(lone, []byte(testPositions), 0o600)

	for _, p := range []string{zipped, folder, lone} {
		got, _, err := ReadExport(p)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(p), err)
			continue
		}
		if len(got.Positions) != 1 || got.Positions[0].Title != "Senior Engineer" {
			t.Errorf("%s: profile = %+v", filepath.Base(p), got)
		}
	}
}

// A renamed file is found by its columns; private files never match.
func TestReadExportFindsRenamedFiles(t *testing.T) {
	dir := t.TempDir()
	p := writeZip(t, dir, "export.zip",
		"messages.csv", "FROM,TO,CONTENT\na,b,private\n",
		"work history.CSV", testPositions,
		"me.csv", "First Name,Last Name,Headline,Summary\nJane,Doe,Engineer,Hi\n")
	got, src, err := ReadExport(p)
	if err != nil {
		t.Fatal(err)
	}
	if src.Positions != "work history.CSV" || src.Profile != "me.csv" || src.HeadersChecked != 1 || got.Name != "Jane Doe" {
		t.Errorf("sources = %+v, profile = %+v", src, got)
	}
}

// Looking for a missing Profile.csv reads other files' first lines, and the
// import says so; a lone renamed CSV has no other files to report.
func TestReadExportCountsCheckedHeaders(t *testing.T) {
	dir := t.TempDir()
	p := writeZip(t, dir, "export.zip", "Positions.csv", testPositions, "messages.csv", "FROM,TO,CONTENT\na,b,private\n")
	if _, src, err := ReadExport(p); err != nil || src.Profile != "" || src.HeadersChecked != 1 {
		t.Errorf("sources = %+v, err = %v", src, err)
	}
	lone := filepath.Join(dir, "jobs.txt")
	os.WriteFile(lone, []byte(testPositions), 0o600)
	if _, src, err := ReadExport(lone); err != nil || src.HeadersChecked != 0 {
		t.Errorf("sources = %+v, err = %v", src, err)
	}
}

func TestReadExportRefusesBadInput(t *testing.T) {
	dir := t.TempDir()
	long := strings.Repeat("x", maxLine+1)
	cases := map[string]struct {
		files []string
		want  string
	}{
		"unsafe path":      {[]string{"../Positions.csv", testPositions}, "unsafe path"},
		"two files":        {[]string{"a/Positions.csv", testPositions, "b/Positions.csv", testPositions}, "more than one"},
		"two lookalikes":   {[]string{"a.csv", testPositions, "b.csv", testPositions}, "more than one"},
		"missing column":   {[]string{"Positions.csv", "Company Name,Title\nExample Co,Engineer\n"}, "missing the columns started on"},
		"ragged row":       {[]string{"Positions.csv", testPositions + "Example Co,Engineer\n"}, "well-formed"},
		"bare quote":       {[]string{"Positions.csv", testPositions + "Ex\"ample,Engineer,,,2020,\n"}, "well-formed"},
		"duplicate column": {[]string{"Positions.csv", "Title,Company Name,Title,Started On\nA,B,C,2020\n"}, "twice"},
		"not UTF-8":        {[]string{"Positions.csv", testPositions + "Caf\xe9,Engineer,,,2020,\n"}, "not UTF-8"},
		"too long":         {[]string{"Positions.csv", testPositions + "Example Co," + long + ",,,2020,\n"}, "over the 300 allowed"},
		"ends first":       {[]string{"Positions.csv", testPositions + "Example Co,Engineer,,,2022,2020\n"}, "impossible end date"},
		"no positions":     {[]string{"Positions.csv", "Company Name,Title,Started On\n"}, "lists no positions"},
		"profile only":     {[]string{"Profile.csv", "First Name,Last Name\nJane,Doe\n"}, "larger data archive"},
	}
	for name, c := range cases {
		_, _, err := ReadExport(writeZip(t, dir, name+".zip", c.files...))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}

func TestReadExportRefusesDamagedZip(t *testing.T) {
	dir := t.TempDir()
	p := writeZip(t, dir, "export.zip", "Positions.csv", testPositions)
	data, _ := os.ReadFile(p)
	data = bytes.Replace(data, []byte("Builds the platform."), []byte("Builds the platfXrm."), 1)
	os.WriteFile(p, data, 0o600)
	if _, _, err := ReadExport(p); err == nil || !strings.Contains(err.Error(), "damaged") {
		t.Errorf("err = %v, want a checksum failure", err)
	}
}

// A link in an unpacked export could point the import at any file.
func TestReadExportRefusesLinks(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.txt")
	os.WriteFile(secret, []byte(testPositions), 0o600)
	folder := filepath.Join(dir, "export")
	os.Mkdir(folder, 0o700)
	if err := os.Symlink(secret, filepath.Join(folder, "Positions.csv")); err != nil {
		t.Skip(err)
	}
	if _, _, err := ReadExport(folder); err == nil || !strings.Contains(err.Error(), "link") {
		t.Errorf("err = %v, want the link refused", err)
	}
}

func TestReadExportCleansText(t *testing.T) {
	dir := t.TempDir()
	p := writeZip(t, dir, "export.zip", "Positions.csv", testPositions+
		"Example\x07 Co,\"Lead\u202e\nEngineer\",\"Line one\r\nLine two\",,2020,2024\n")
	got, _, err := ReadExport(p)
	if err != nil {
		t.Fatal(err)
	}
	if r := got.Positions[1]; r.Title != "Lead Engineer" || r.Company != "Example Co" || r.Description != "Line one\nLine two" {
		t.Errorf("position = %+v", r)
	}
}

// A profile read back from the career folder is checked as an import is.
func TestValidateProfile(t *testing.T) {
	good := Profile{Name: "Jane Doe", Positions: []Position{{ID: "r1", Title: "Engineer", Start: "2020-01", End: "2024-02"}}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Profile){
		"control character": func(p *Profile) { p.Positions[0].Title = "Eng\x1b[31mineer" },
		"bidi override":     func(p *Profile) { p.Headline = "abc\u202edef" },
		"bad month":         func(p *Profile) { p.Positions[0].Start = "2020-13" },
		"future":            func(p *Profile) { p.Positions[0].Start = "2999-01" },
		"duplicate ID":      func(p *Profile) { p.Positions = append(p.Positions, p.Positions[0]) },
		"long official":     func(p *Profile) { p.Positions[0].Official = strings.Repeat("x", maxOfficial+1) },
		"no title":          func(p *Profile) { p.Positions[0].Title = " " },
		"no positions":      func(p *Profile) { p.Positions = nil },
	} {
		p := good
		p.Positions = append([]Position(nil), good.Positions...)
		change(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
