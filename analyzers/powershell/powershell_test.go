package powershell

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/rburns629/urfluency-cli/analysis"
	"github.com/rburns629/urfluency-cli/rules"
)

func analyze(t *testing.T, src string) []analysis.Finding {
	t.Helper()
	got, err := Analyzer{}.Analyze(context.Background(), []analysis.File{{Path: "scripts/a.ps1", Content: []byte(src)}})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestRules(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{
			name: "Invoke-Expression and iex, including a download piped into it",
			src: `Invoke-Expression $command
Invoke-WebRequest https://example.com/i.ps1 | iex
`,
			want: []string{"powershell.invoke-expression:1", "powershell.invoke-expression:2"},
		},
		{
			name: "array grown with += in a loop, once per array",
			src: `$out = @()
foreach ($i in $items) {
    $out += $i
    $out += $i.Name
}
$total = 0
$names = "a"
for ($j = 0; $j -lt 3; $j++) { $total += $j; $names += "b" }
$once = @()
$once += 1
function Get-X {
    $rows = @( )
    Get-Item * | ForEach-Object { $rows += $_ }
    while ($true) { $rows += 1 }
}
function Get-Y {
    $seen = @()
    while ($true) { $seen += 1 }
}
`,
			want: []string{"powershell.array-append-in-loop:13", "powershell.array-append-in-loop:18", "powershell.array-append-in-loop:3"},
		},
		{
			name: "empty catch, but not one with a comment saying why",
			src: `try { Get-Item x } catch { }
try { Get-Item y } catch {
    # The file is optional.
}
`,
			want: []string{"powershell.empty-catch:1"},
		},
		{
			name: "aliases on every platform, but not native programs or full names",
			src: `gci | % { $_.Name }
Get-ChildItem | ForEach-Object { $_.Name }
ls -la
`,
			want: []string{"powershell.cmdlet-alias:1", "powershell.cmdlet-alias:1"},
		},
		{
			name: "SecureString from a literal, not from a variable",
			src: `$a = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
$b = ConvertTo-SecureString $fromVault -AsPlainText -Force
`,
			want: []string{"powershell.plaintext-secure-string:1"},
		},
		{
			name: "certificate checks turned off",
			src: `Invoke-RestMethod https://localhost -SkipCertificateCheck
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
`,
			want: []string{"powershell.skip-certificate-check:1", "powershell.skip-certificate-check:2"},
		},
		{
			name: "global variables, not script scope",
			src: `$global:Config = @{}
$script:Config = @{}
`,
			want: []string{"powershell.global-variable:1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := []string{}
			for _, f := range analyze(t, tt.src) {
				if f.Positive {
					continue
				}
				if _, ok := rules.Lookup(f.Rule); !ok {
					t.Errorf("%s is not in the catalog", f.Rule)
				}
				got = append(got, fmt.Sprintf("%s:%d", f.Rule, f.Line))
			}
			sort.Strings(got)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIdioms(t *testing.T) {
	src := `<#
.SYNOPSIS
Copies a release.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Copy-Release {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )
    process {
        $params = @{ Path = $Path; Destination = 'out' }
        Copy-Item @params
    }
}
`
	got := map[string]bool{}
	for _, f := range analyze(t, src) {
		if f.Positive {
			got[f.Rule] = true
		} else {
			t.Errorf("unexpected finding %s:%d", f.Rule, f.Line)
		}
	}
	for _, r := range rules.ForLanguage("powershell") {
		if r.Category == rules.Idiom && !got[r.ID] {
			t.Errorf("%s not found", r.ID)
		}
	}
}

// sort, write, and rmdir run native programs on Linux and macOS.
func TestNativeNamesAreNotAliases(t *testing.T) {
	for _, f := range analyze(t, "Get-Content a.txt | sort\nwrite \"done\"\nrmdir build\n") {
		if f.Rule == "powershell.cmdlet-alias" {
			t.Errorf("line %d reported as an alias", f.Line)
		}
	}
}

// Pester tests use Invoke-Expression and globals to drive prompts; scripts
// in the module are still reported.
func TestTestsMayUseInvokeExpressionAndGlobals(t *testing.T) {
	src := "Invoke-Expression $cmd\n$global:GitPromptSettings = 1\n"
	got, err := Analyzer{}.Analyze(context.Background(), []analysis.File{{Path: "test/DefaultPrompt.Tests.ps1", Content: []byte(src)}})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range got {
		if f.Rule == "powershell.invoke-expression" || f.Rule == "powershell.global-variable" {
			t.Errorf("test file: got %s", f.Rule)
		}
	}
	if n := len(analyze(t, src)); n < 2 {
		t.Errorf("script: got %d findings, want both", n)
	}
}
