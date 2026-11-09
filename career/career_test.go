package career

import (
	"archive/zip"
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
	p, err := ReadExport(zipPath)
	if err != nil {
		t.Fatal(err)
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
