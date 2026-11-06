package rules

// Era is when a rule's practice became possible (Introduced) and the expected
// norm (Established), as years. A rule whose problem was never good practice,
// such as a handler that only re-raises, has the zero Era. See DESIGN.md,
// "Era-aware findings".
type Era struct {
	Introduced  int
	Established int
}

// Weight is how much a finding on a line from year counts: nothing before the
// practice was possible, half while it was optional, and in full after. A
// rule without an era, or a line without a year, counts in full.
func (e Era) Weight(year int) float64 {
	switch {
	case e.Introduced == 0 || year == 0:
		return 1
	case year < e.Introduced:
		return 0
	case year < e.Established:
		return 0.5
	}
	return 1
}

// eras are the eras of this catalog's rules, each from a cited release.
// Rules registered elsewhere, such as the engine's, set Era themselves.
var eras = map[string]Era{
	// PEP 484 in Python 3.5 (2015). Python 2, which cannot parse annotations,
	// reached end of life in January 2020.
	"py.unannotated-public-function": {2015, 2020},
	"py.idiom.type-hints":            {2015, 2020},
	"py.type-ignore":                 {2015, 2020},
	// PEP 498 in Python 3.6 (December 2016).
	"py.idiom.f-string": {2017, 2019},
	// PEP 557 dataclasses in Python 3.7 (2018).
	"py.idiom.structured-data": {2018, 2020},
	// PEP 492 in Python 3.5 (2015); asyncio no longer provisional from 3.6.
	"py.idiom.async": {2015, 2018},
	// pathlib in Python 3.4 (2014); os.PathLike across the standard library in 3.6.
	"py.idiom.pathlib": {2014, 2019},
	// PEP 544 in Python 3.8 (2019).
	"py.idiom.protocol": {2019, 2021},
	// %w, errors.Is, and errors.As in Go 1.13 (2019).
	"go.idiom.error-wrapping":   {2019, 2020},
	"go.idiom.error-inspection": {2019, 2020},
	// Type parameters in Go 1.18 (2022).
	"go.idiom.generics": {2022, 2023},
}
