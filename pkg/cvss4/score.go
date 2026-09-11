package cvss4

import "errors"

// ErrScoringUnavailable indicates that a vector model is available but the
// normative CVSS v4.0 MacroVector lookup implementation is not yet bundled.
// It is deliberately returned instead of producing an approximation.
var ErrScoringUnavailable = errors.New("CVSS v4.0 scoring is unavailable")

// Score is reserved for the normative CVSS v4.0 MacroVector calculation.
// Parsing and validation are available now; callers must handle this error
// until the FIRST lookup tables and interpolation algorithm are integrated.
func (v *Vector) Score() (float64, error) {
	if err := v.Validate(); err != nil {
		return 0, err
	}
	return 0, ErrScoringUnavailable
}
