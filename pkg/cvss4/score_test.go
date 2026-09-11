package cvss4

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestScoreRequiresNormativeLookup(t *testing.T) {
	v, err := Parse(complete)
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Score()
	if !errors.Is(err, ErrScoringUnavailable) {
		t.Fatalf("got %v, want ErrScoringUnavailable", err)
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
