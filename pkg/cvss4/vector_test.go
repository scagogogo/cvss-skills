package cvss4

import (
	"errors"
	"testing"
)

const complete = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

func TestParseAndCanonicalString(t *testing.T) {
	v, err := Parse("CVSS:4.0/SA:N/SI:N/SC:N/VA:H/VI:H/VC:H/UI:N/PR:N/AT:N/AC:L/AV:N")
	if err != nil {
		t.Fatal(err)
	}
	if got := v.String(); got != complete {
		t.Fatalf("got %q, want %q", got, complete)
	}
}

func TestParseRejectsInvalidVectors(t *testing.T) {
	cases := []struct {
		name, input string
		target      error
	}{
		{"prefix", "CVSS:3.1/AV:N", ErrInvalidPrefix},
		{"missing", "CVSS:4.0/AV:N", ErrMissingMetric},
		{"duplicate", complete + "/AV:N", ErrDuplicateMetric},
		{"name", complete + "/ZZ:N", ErrInvalidMetricName},
		{"value", "CVSS:4.0/AV:Z/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", ErrInvalidMetric},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.input)
			if !errors.Is(err, tc.target) {
				t.Fatalf("error %v does not wrap %v", err, tc.target)
			}
		})
	}
}

func TestSetAndGet(t *testing.T) {
	v := New()
	if err := v.Set("av", "n"); err != nil {
		t.Fatal(err)
	}
	if got, ok := v.Get("AV"); !ok || got != "N" {
		t.Fatalf("got %q, %v", got, ok)
	}
}

func TestValidateNil(t *testing.T) {
	var v *Vector
	if v.Validate() == nil {
		t.Fatal("nil vector validated")
	}
}
