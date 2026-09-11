package cvss2

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestParseAndScore(t *testing.T) {
	v, err := Parse("AV:N/AC:L/Au:N/C:P/I:P/A:P")
	if err != nil {
		t.Fatal(err)
	}
	score, err := v.Score()
	if err != nil {
		t.Fatal(err)
	}
	if score != 7.5 {
		t.Fatalf("got %.1f, want 7.5", score)
	}
	if got := v.String(); got != "AV:N/AC:L/Au:N/C:P/I:P/A:P" {
		t.Fatalf("canonical vector: %q", got)
	}
}

func TestParsePrefixedAndCaseInsensitive(t *testing.T) {
	v, err := Parse("cvss:2.0/av:n/ac:l/au:n/c:p/i:p/a:p")
	if err != nil {
		t.Fatal(err)
	}
	if v.String() != "AV:N/AC:L/Au:N/C:P/I:P/A:P" {
		t.Fatalf("got %q", v.String())
	}
}

func TestTemporalAndEnvironmental(t *testing.T) {
	v, err := Parse("AV:N/AC:L/Au:N/C:P/I:P/A:P/E:POC/RL:OF/RC:UC/CDP:L/TD:H/CR:H/IR:M/AR:L")
	if err != nil {
		t.Fatal(err)
	}
	s, err := v.Calculate()
	if err != nil {
		t.Fatal(err)
	}
	if !s.HasTemporal || !s.HasEnvironmental {
		t.Fatal("expected temporal and environmental scores")
	}
	if s.TemporalScore >= s.BaseScore {
		t.Fatal("temporal multiplier should reduce this score")
	}
}

// TestScoreMatchesReference pins scores validated against the Red Hat cvss
// reference implementation, exercising the v2 requirements (H=1.51), the
// RL:TF=0.90 temporal constant, and the half-up environmental rounding.
func TestScoreMatchesReference(t *testing.T) {
	cases := []struct {
		vector string
		base   float64
		temp   float64
		env    float64
	}{
		{"AV:L/AC:H/Au:M/C:C/I:P/A:N", 4.4, 4.4, 4.4},
		{"AV:L/AC:H/Au:N/C:C/I:C/A:N/E:H/RL:W/RC:UC", 5.6, 4.8, 4.8},
		{"AV:A/AC:H/Au:M/C:P/I:N/A:P/E:F/RL:OF/RC:C/CDP:MH/TD:N/CR:M/IR:L/AR:H", 2.7, 2.2, 0.0},
		{"AV:A/AC:M/Au:S/C:P/I:N/A:N/E:POC/RL:TF/RC:UC/CDP:N/TD:H/CR:H/IR:H/AR:L", 2.3, 1.7, 2.5},
		{"AV:L/AC:H/Au:M/C:P/I:N/A:P/E:POC/RL:TF/RC:UC/CDP:L/TD:L/CR:M/IR:H/AR:H", 2.3, 1.7, 0.8},
	}
	for _, c := range cases {
		v, err := Parse(c.vector)
		if err != nil {
			t.Fatalf("%s: %v", c.vector, err)
		}
		s, err := v.Calculate()
		if err != nil {
			t.Fatalf("%s: %v", c.vector, err)
		}
		if s.BaseScore != c.base || s.TemporalScore != c.temp || s.EnvironmentalScore != c.env {
			t.Errorf("%s: got (%.1f, %.1f, %.1f), want (%.1f, %.1f, %.1f)",
				c.vector, s.BaseScore, s.TemporalScore, s.EnvironmentalScore, c.base, c.temp, c.env)
		}
	}
}

func TestValidationAndJSON(t *testing.T) {
	_, err := Parse("AV:N/AC:L/Au:N/C:P/I:P")
	if !errors.Is(err, ErrMissingMetric) {
		t.Fatalf("got %v", err)
	}
	v, err := Parse("AV:N/AC:L/Au:N/C:P/I:P/A:P")
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
	if got.String() != v.String() {
		t.Fatalf("round trip: %q != %q", got.String(), v.String())
	}
}
