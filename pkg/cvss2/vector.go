// Package cvss2 implements CVSS v2.0 vector parsing, validation, and scoring.
package cvss2

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
)

var (
	ErrMissingMetric     = errors.New("missing required CVSS v2.0 metric")
	ErrDuplicateMetric   = errors.New("duplicate CVSS v2.0 metric")
	ErrInvalidMetric     = errors.New("invalid CVSS v2.0 metric value")
	ErrInvalidMetricName = errors.New("invalid CVSS v2.0 metric name")
)

// Vector is a CVSS v2.0 vector. Values are the short metric values.
type Vector struct{ metrics map[string]string }

// New returns an empty CVSS v2.0 vector.
func New() *Vector { return &Vector{metrics: make(map[string]string)} }

// Parse parses a CVSS v2.0 vector string. No "CVSS:" prefix is required; a
// leading "CVSS:2.0/" is stripped if present.
func Parse(s string) (*Vector, error) {
	raw := strings.TrimSpace(s)
	if strings.HasPrefix(strings.ToUpper(raw), "CVSS:2.0/") {
		raw = raw[len("CVSS:2.0/"):]
	} else if strings.HasPrefix(strings.ToUpper(raw), "CVSS:2.0") {
		raw = ""
	}
	v := New()
	for _, part := range strings.Split(raw, "/") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		pair := strings.SplitN(part, ":", 2)
		if len(pair) != 2 || pair[0] == "" || pair[1] == "" {
			return nil, fmt.Errorf("%w: %q", ErrInvalidMetric, part)
		}
		key := canonicalName(pair[0])
		value, ok := normalizeValue(key, pair[1])
		if !ok {
			if _, known := metricValues[key]; !known {
				return nil, fmt.Errorf("%w: %s", ErrInvalidMetricName, key)
			}
			return nil, fmt.Errorf("%w: %s:%s", ErrInvalidMetric, key, pair[1])
		}
		if _, known := metricValues[key]; !known {
			return nil, fmt.Errorf("%w: %s", ErrInvalidMetricName, key)
		}
		if _, ok := v.metrics[key]; ok {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateMetric, key)
		}
		v.metrics[key] = value
	}
	if err := v.Validate(); err != nil {
		return nil, err
	}
	return v, nil
}

// Validate checks that all required Base metrics are present.
func (v *Vector) Validate() error {
	if v == nil {
		return errors.New("nil CVSS v2.0 vector")
	}
	for _, key := range []string{"AV", "AC", "Au", "C", "I", "A"} {
		if _, ok := v.metrics[key]; !ok {
			return fmt.Errorf("%w: %s", ErrMissingMetric, key)
		}
	}
	return nil
}

// Get returns a metric value and whether it was supplied.
func (v *Vector) Get(name string) (string, bool) {
	if v == nil {
		return "", false
	}
	value, ok := v.metrics[canonicalName(name)]
	return value, ok
}

// MarshalJSON serializes a vector as its canonical v2.0 vector string.
func (v *Vector) MarshalJSON() ([]byte, error) { return json.Marshal(v.String()) }

// UnmarshalJSON parses a JSON string containing a v2.0 vector.
func (v *Vector) UnmarshalJSON(data []byte) error {
	var s *string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == nil {
		return nil
	}
	parsed, err := Parse(*s)
	if err != nil {
		return err
	}
	*v = *parsed
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (v *Vector) MarshalText() ([]byte, error) { return []byte(v.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (v *Vector) UnmarshalText(data []byte) error {
	parsed, err := Parse(string(data))
	if err != nil {
		return err
	}
	*v = *parsed
	return nil
}

// String returns the canonical CVSS v2.0 vector ordering.
func (v *Vector) String() string {
	if v == nil {
		return ""
	}
	keys := append([]string(nil), canonicalOrder...)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		if value, ok := v.metrics[key]; ok {
			out = append(out, key+":"+value)
		}
	}
	return strings.Join(out, "/")
}

var canonicalOrder = []string{"AV", "AC", "Au", "C", "I", "A", "E", "RL", "RC", "CDP", "TD", "CR", "IR", "AR", "MAV", "MAC", "MAu", "MC", "MI", "MA"}

func canonicalName(name string) string {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "AV":
		return "AV"
	case "AC":
		return "AC"
	case "AU", "AU:":
		return "Au"
	case "C":
		return "C"
	case "I":
		return "I"
	case "A":
		return "A"
	case "E":
		return "E"
	case "RL":
		return "RL"
	case "RC":
		return "RC"
	case "CDP":
		return "CDP"
	case "TD":
		return "TD"
	case "CR":
		return "CR"
	case "IR":
		return "IR"
	case "AR":
		return "AR"
	case "MAV":
		return "MAV"
	case "MAC":
		return "MAC"
	case "MAU":
		return "MAu"
	case "MC":
		return "MC"
	case "MI":
		return "MI"
	case "MA":
		return "MA"
	}
	return strings.ToUpper(strings.TrimSpace(name))
}

var metricValues = map[string][]string{
	"AV":  {"N", "A", "L"},
	"AC":  {"H", "M", "L"},
	"Au":  {"M", "S", "N"},
	"C":   {"N", "P", "C"},
	"I":   {"N", "P", "C"},
	"A":   {"N", "P", "C"},
	"E":   {"U", "POC", "F", "H", "ND"},
	"RL":  {"OF", "TF", "W", "U", "ND"},
	"RC":  {"UC", "UR", "C", "ND"},
	"CDP": {"N", "L", "LM", "MH", "H", "ND"},
	"TD":  {"N", "L", "M", "H", "ND"},
	"CR":  {"L", "M", "H", "ND"},
	"IR":  {"L", "M", "H", "ND"},
	"AR":  {"L", "M", "H", "ND"},
	"MAV": {"N", "A", "L", "ND"},
	"MAC": {"H", "M", "L", "ND"},
	"MAu": {"M", "S", "N", "ND"},
	"MC":  {"N", "P", "C", "ND"},
	"MI":  {"N", "P", "C", "ND"},
	"MA":  {"N", "P", "C", "ND"},
}

func normalizeValue(key, value string) (string, bool) {
	upper := strings.ToUpper(strings.TrimSpace(value))
	if key == "Au" {
		upper = strings.Replace(upper, "AU", "Au", 1)
	}
	for _, allowed := range metricValues[key] {
		if strings.EqualFold(allowed, upper) {
			return upper, true
		}
	}
	return "", false
}

// score tables
var avScore = map[string]float64{"N": 1.0, "A": 0.646, "L": 0.395}
var acScore = map[string]float64{"H": 0.35, "M": 0.61, "L": 0.71}
var auScore = map[string]float64{"M": 0.45, "S": 0.56, "N": 0.704}
var cioScore = map[string]float64{"N": 0.0, "P": 0.275, "C": 0.660}
var eScore = map[string]float64{"U": 0.85, "POC": 0.90, "F": 0.95, "H": 1.0, "ND": 1.0}
var rlScore = map[string]float64{"OF": 0.87, "TF": 0.90, "W": 0.95, "U": 1.0, "ND": 1.0}
var rcScore = map[string]float64{"UC": 0.90, "UR": 0.95, "C": 1.0, "ND": 1.0}
var cdpScore = map[string]float64{"N": 0.0, "L": 0.1, "LM": 0.3, "MH": 0.4, "H": 0.5, "ND": 0.0}
var tdScore = map[string]float64{"N": 0.0, "L": 0.25, "M": 0.75, "H": 1.0, "ND": 1.0}
var reqScore = map[string]float64{"L": 0.5, "M": 1.0, "H": 1.51, "ND": 1.0}

func fImpact(impact float64) float64 {
	if impact == 0 {
		return 0
	}
	return 1.176
}

// roundToOne rounds to one decimal place using CVSS v2's half-up semantics.
// The small epsilon keeps decimal half-way values stable across binary floats.
func roundToOne(x float64) float64 {
	return math.Floor(x*10+0.5+1e-9) / 10
}
