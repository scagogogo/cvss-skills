package cvss4

import (
	"encoding/json"
	"testing"
)

func TestScoreUsesNormativeLookupAndInterpolation(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		want   float64
	}{
		{"base", complete, 9.3},
		{"threat", "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:P", 4.5},
		{"no impact", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0},
		{"downstream scope", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:S/SA:S", 10},
		{"low-end threat", "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:U/CR:L/IR:L/AR:L", 0.1},
		{"modified environment", "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N/E:P/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:N/MVC:H/MSC:H/MSI:S/MSA:S", 9.5},
		{"supplemental scope", "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:P/CR:M/IR:M/AR:M/MUI:A/MVC:L/MSA:S", 5.1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := Parse(tt.vector)
			if err != nil {
				t.Fatal(err)
			}
			got, err := v.Score()
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("score = %.1f, want %.1f", got, tt.want)
			}
		})
	}
}

func TestSeverity(t *testing.T) {
	v, err := Parse(complete)
	if err != nil {
		t.Fatal(err)
	}
	severity, err := v.Severity()
	if err != nil {
		t.Fatal(err)
	}
	if severity != "Critical" {
		t.Fatalf("severity = %q, want Critical", severity)
	}
}

func TestJSONRoundTrip(t *testing.T) {
	v, err := Parse(complete)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var got Vector
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.String() != complete {
		t.Fatalf("got %q, want %q", got.String(), complete)
	}
}
