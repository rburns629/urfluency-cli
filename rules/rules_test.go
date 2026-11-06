package rules

import "testing"

func TestCatalogIsComplete(t *testing.T) {
	if d := Duplicates(); len(d) > 0 {
		t.Fatalf("duplicate rule IDs: %v", d)
	}
	valid := map[Category]bool{CleanCode: true, Architecture: true, TypeSafety: true, LanguageProficiency: true, Security: true, AIEngineering: true, Idiom: true}
	for id, r := range catalog {
		// Idioms are strengths, so they have no focus advice.
		if r.ID != id || r.Title == "" || r.Why == "" || (r.Focus == "") != (r.Category == Idiom) || len(r.Languages) == 0 {
			t.Errorf("rule %s is missing fields: %+v", id, r)
		}
		if !valid[r.Category] {
			t.Errorf("rule %s has unknown category %q", id, r.Category)
		}
	}
}

func TestStandards(t *testing.T) {
	tests := map[string]string{
		"clean.cognitive-complexity":    "standards/ARCHITECTURE.md#simplest-sufficient-solution",
		"ts.explicit-any":               "standards/TYPE_SAFETY.md",
		"sec.api-token":                 "standards/SECURITY.md",
		"prompt.unverified-change":      "standards/QUALITY_GATES.md",
		"go.waitgroup-add-in-goroutine": "",
	}
	for id, want := range tests {
		r, ok := Lookup(id)
		if !ok {
			t.Fatalf("rule %s missing", id)
		}
		got := r.Standard()
		if want == "" && got != "" || want != "" && got != standardsBase+want {
			t.Errorf("%s standard = %q, want %q", id, got, want)
		}
	}
}

func TestEras(t *testing.T) {
	e := Era{Introduced: 2015, Established: 2020}
	for _, c := range []struct {
		year int
		want float64
	}{{0, 1}, {2014, 0}, {2015, 0.5}, {2019, 0.5}, {2020, 1}, {2026, 1}} {
		if got := e.Weight(c.year); got != c.want {
			t.Errorf("Weight(%d) = %v, want %v", c.year, got, c.want)
		}
	}
	if got := (Era{}).Weight(2001); got != 1 {
		t.Errorf("a rule without an era weighs %v, want 1", got)
	}
	// Every era names a rule in the catalog, in order.
	for id, e := range eras {
		r, ok := Lookup(id)
		if !ok {
			t.Errorf("era for unknown rule %s", id)
			continue
		}
		if r.Era != e || e.Introduced > e.Established || e.Introduced < 2000 {
			t.Errorf("%s: era %+v, catalog %+v", id, e, r.Era)
		}
	}
	// Practices that were never good get no era.
	for _, id := range []string{"py.bare-except", "py.mutable-default-argument"} {
		if r, _ := Lookup(id); r.Era != (Era{}) {
			t.Errorf("%s has era %+v, want none", id, r.Era)
		}
	}
}
