// Package cvss4 implements CVSS v4.0 vector parsing and validation.
package cvss4

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

var (
	ErrInvalidPrefix     = errors.New("invalid CVSS v4.0 prefix")
	ErrMissingMetric     = errors.New("missing required CVSS v4.0 metric")
	ErrDuplicateMetric   = errors.New("duplicate CVSS v4.0 metric")
	ErrInvalidMetric     = errors.New("invalid CVSS v4.0 metric value")
	ErrInvalidMetricName = errors.New("invalid CVSS v4.0 metric name")
)

// Vector is a CVSS v4.0 vector. Values are the short metric values.
type Vector struct{ metrics map[string]string }

// New returns an empty CVSS v4.0 vector.
func New() *Vector { return &Vector{metrics: make(map[string]string)} }

// Parse parses a CVSS v4.0 vector string. Base metrics are required; other
// metric groups are optional and use the specification's Not Defined values.
func Parse(s string) (*Vector, error) {
	parts := strings.Split(strings.TrimSpace(s), "/")
	if len(parts) == 0 || parts[0] != "CVSS:4.0" {
		return nil, fmt.Errorf("%w: expected CVSS:4.0", ErrInvalidPrefix)
	}
	v := New()
	for _, part := range parts[1:] {
		if part == "" {
			return nil, fmt.Errorf("%w: empty metric", ErrInvalidMetric)
		}
		pair := strings.SplitN(part, ":", 2)
		if len(pair) != 2 || pair[0] == "" || pair[1] == "" {
			return nil, fmt.Errorf("%w: %q", ErrInvalidMetric, part)
		}
		key := strings.ToUpper(pair[0])
		value, ok := normalizeMetricValue(key, pair[1])
		if !ok {
			if _, known := metricValues[key]; !known {
				return nil, fmt.Errorf("%w: %s", ErrInvalidMetricName, key)
			}
			return nil, fmt.Errorf("%w: %s:%s", ErrInvalidMetric, key, pair[1])
		}
		if _, ok := metricValues[key]; !ok {
			return nil, fmt.Errorf("%w: %s", ErrInvalidMetricName, key)
		}
		if _, ok := v.metrics[key]; ok {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateMetric, key)
		}
		if !validMetricValue(key, value) {
			return nil, fmt.Errorf("%w: %s:%s", ErrInvalidMetric, key, value)
		}
		v.metrics[key] = value
	}
	if err := v.Validate(); err != nil {
		return nil, err
	}
	return v, nil
}

// Validate checks required Base metrics and all supplied values.
func (v *Vector) Validate() error {
	if v == nil {
		return errors.New("nil CVSS v4.0 vector")
	}
	for _, key := range baseOrder {
		if _, ok := v.metrics[key]; !ok {
			return fmt.Errorf("%w: %s", ErrMissingMetric, key)
		}
	}
	for key, value := range v.metrics {
		if !validMetricValue(key, value) {
			return fmt.Errorf("%w: %s:%s", ErrInvalidMetric, key, value)
		}
	}
	return nil
}

// Get returns a metric value and whether it was explicitly supplied.
func (v *Vector) Get(name string) (string, bool) {
	if v == nil {
		return "", false
	}
	value, ok := v.metrics[strings.ToUpper(name)]
	return value, ok
}

// Set sets a metric after validating its name and value.
func (v *Vector) Set(name, value string) error {
	if v == nil {
		return errors.New("nil CVSS v4.0 vector")
	}
	key := strings.ToUpper(name)
	val, ok := normalizeMetricValue(key, value)
	if _, known := metricValues[key]; !known {
		return fmt.Errorf("%w: %s", ErrInvalidMetricName, key)
	}
	if !ok {
		return fmt.Errorf("%w: %s:%s", ErrInvalidMetric, key, value)
	}
	if v.metrics == nil {
		v.metrics = make(map[string]string)
	}
	v.metrics[key] = val
	return nil
}

// MarshalJSON serializes a vector as its canonical vector string.
func (v *Vector) MarshalJSON() ([]byte, error) { return json.Marshal(v.String()) }

// UnmarshalJSON parses a JSON string containing a CVSS v4.0 vector.
func (v *Vector) UnmarshalJSON(data []byte) error {
	var s *string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("CVSS v4.0 vector must be a JSON string or null: %w", err)
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

// String returns the canonical CVSS v4.0 vector ordering.
func (v *Vector) String() string {
	if v == nil {
		return ""
	}
	keys := append([]string(nil), canonicalOrder...)
	// Keep future/unknown programmatically-created keys deterministic.
	for key := range v.metrics {
		found := false
		for _, known := range keys {
			if key == known {
				found = true
				break
			}
		}
		if !found {
			keys = append(keys, key)
		}
	}
	known := make(map[string]bool, len(canonicalOrder))
	for _, key := range canonicalOrder {
		known[key] = true
	}
	sort.SliceStable(keys, func(i, j int) bool {
		if known[keys[i]] && known[keys[j]] {
			return indexOf(canonicalOrder, keys[i]) < indexOf(canonicalOrder, keys[j])
		}
		return keys[i] < keys[j]
	})
	out := []string{"CVSS:4.0"}
	for _, key := range keys {
		if value, ok := v.metrics[key]; ok {
			out = append(out, key+":"+value)
		}
	}
	return strings.Join(out, "/")
}

func indexOf(values []string, target string) int {
	for i, value := range values {
		if value == target {
			return i
		}
	}
	return len(values)
}

var baseOrder = []string{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}
var canonicalOrder = []string{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA", "E", "CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA", "S", "AU", "R", "V", "RE", "U"}

var metricValues = map[string][]string{
	"AV": {"N", "A", "L", "P"}, "AC": {"L", "H"}, "AT": {"N", "P"}, "PR": {"N", "L", "H"}, "UI": {"N", "P", "A"},
	"VC": {"N", "L", "H"}, "VI": {"N", "L", "H"}, "VA": {"N", "L", "H"}, "SC": {"N", "L", "H"}, "SI": {"N", "L", "H", "S"}, "SA": {"N", "L", "H", "S"},
	"E": {"X", "A", "P", "U"}, "CR": {"X", "H", "M", "L"}, "IR": {"X", "H", "M", "L"}, "AR": {"X", "H", "M", "L"},
	"MAV": {"X", "N", "A", "L", "P"}, "MAC": {"X", "L", "H"}, "MAT": {"X", "N", "P"}, "MPR": {"X", "N", "L", "H"}, "MUI": {"X", "N", "P", "A"},
	"MVC": {"X", "N", "L", "H"}, "MVI": {"X", "N", "L", "H"}, "MVA": {"X", "N", "L", "H"}, "MSC": {"X", "N", "L", "H"}, "MSI": {"X", "N", "L", "H", "S"}, "MSA": {"X", "N", "L", "H", "S"},
	"S": {"X", "N", "P"}, "AU": {"X", "N", "Y"}, "R": {"X", "A", "I"}, "V": {"X", "D", "C"}, "RE": {"X", "L", "M", "H"}, "U": {"X", "Clear", "Green", "Amber", "Red"},
}

func normalizeMetricValue(key, value string) (string, bool) {
	for _, allowed := range metricValues[key] {
		if strings.EqualFold(allowed, value) {
			return allowed, true
		}
	}
	return "", false
}

func validMetricValue(key, value string) bool {
	_, ok := normalizeMetricValue(key, value)
	return ok
}
