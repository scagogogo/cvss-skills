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
