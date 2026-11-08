package upload

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func valid() Payload {
	return Payload{Format: Format, Tool: "0.1.8", Report: "0.4", Catalog: "0.10", Model: "0.2-uncalibrated", Tier: SelfReported, Since: "all",
		Summary:  json.RawMessage(`{"headline":"Advanced by code","strengths":["Go, 84"],"ratings":[{"area":"language","name":"go","score":84}]}`),
		Combined: json.RawMessage(`{"repositories":94,"languages":[{"language":"go","owned_lines":79990}]}`),
		Facts:    json.RawMessage(`{"format":"1","git":{"repos":94,"languages":[{"name":"go","owned_lines":79990,"findings_by_rule":{"go.ignored-error":3}}]}}`)}
}

func TestValidate(t *testing.T) {
	if err := Validate(valid()); err != nil {
		t.Fatalf("valid payload rejected: %v", err)
	}
	// Text a real summary carries: URLs, ratios, versions, and a dated since.
	ok := valid()
	ok.Since = "2025-01-01"
	ok.Summary = json.RawMessage(`{"headline":"See https://github.com/roburns/clean-agent-code/blob/main/README.md","strengths":["Go: 84/100 (Advanced); 1,234 lines","Uses A:B ratios and v1.2.3"]}`)
	if err := Validate(ok); err != nil {
		t.Errorf("ordinary summary text rejected: %v", err)
	}
	tests := []struct {
		name        string
		edit        func(*Payload)
		identifying bool
	}{
		{"wrong format", func(p *Payload) { p.Format = "0" }, false},
		{"claims verified", func(p *Payload) { p.Tier = "verified" }, false},
		{"missing tool", func(p *Payload) { p.Tool = "" }, false},
		{"summary not an object", func(p *Payload) { p.Summary = json.RawMessage(`[]`) }, false},
		{"format 1, without facts", func(p *Payload) { p.Format, p.Facts = "1", nil }, false},
		{"missing facts", func(p *Payload) { p.Facts = nil }, false},
		{"facts not an object", func(p *Payload) { p.Facts = json.RawMessage(`[1]`) }, false},
		{"repository label in facts", func(p *Payload) { p.Facts = json.RawMessage(`{"git":{"projects":[{"label":"work/api"}]}}`) }, true},
		{"path in facts", func(p *Payload) { p.Facts = json.RawMessage(`{"git":{"languages":[{"name":"/Users/ana/work/api"}]}}`) }, true},
		{"locations", func(p *Payload) {
			p.Combined = json.RawMessage(`{"languages":[{"weaknesses":[{"locations":["a.go:1"]}]}]}`)
		}, true},
		{"repository name", func(p *Payload) { p.Combined = json.RawMessage(`{"quality_gates":[{"repository":"acme/api"}]}`) }, true},
		{"email in text", func(p *Payload) { p.Summary = json.RawMessage(`{"strengths":["by someone@example.com"]}`) }, true},
		{"home path", func(p *Payload) { p.Summary = json.RawMessage(`{"caveats":["scanned /Users/someone/work"]}`) }, true},
		{"commit hash", func(p *Payload) {
			p.Summary = json.RawMessage(`{"headline":"at 0123456789abcdef0123456789abcdef01234567"}`)
		}, true},
	}
	for _, leak := range []struct{ name, summary string }{
		{"path as a key", `{"rules":{"/Users/ana/acme":1}}`},
		{"email as a key", `{"rules":{"ana@corp.example":1}}`},
		{"temporary folder", `{"caveats":["read /var/folders/x/T/scan"]}`},
		{"private folder", `{"caveats":["read /private/tmp/scan"]}`},
		{"tmp", `{"caveats":["at=/tmp/acme"]}`},
		{"Windows path with slashes", `{"caveats":["C:/Users/ana/acme"]}`},
		{"Windows path after =", `{"caveats":["dir=C:\\work\\acme"]}`},
		{"upper-case hash", `{"headline":"0123456789ABCDEF0123456789ABCDEF01234567"}`},
		{"SHA-256 hash", `{"headline":"` + strings.Repeat("ab", 32) + `"}`},
	} {
		tests = append(tests, struct {
			name        string
			edit        func(*Payload)
			identifying bool
		}{leak.name, func(p *Payload) { p.Summary = json.RawMessage(leak.summary) }, true})
	}
	tests = append(tests, []struct {
		name        string
		edit        func(*Payload)
		identifying bool
	}{
		{"email in since", func(p *Payload) { p.Since = "ana@corp.example" }, true},
		{"since not a date", func(p *Payload) { p.Since = "last week" }, false},
		{"path in tool", func(p *Payload) { p.Tool = "/home/ana/bin" }, true},
	}...)
	for _, tc := range tests {
		p := valid()
		tc.edit(&p)
		err := Validate(p)
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
			continue
		}
		if errors.Is(err, ErrIdentifying) != tc.identifying {
			t.Errorf("%s: error %v, identifying = %v", tc.name, err, tc.identifying)
		}
	}
}
