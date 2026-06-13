package parser

import (
	"testing"
)

func TestBatchParse(t *testing.T) {
	vectors := []string{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N",
		"INVALID",
	}
	results := BatchParse(vectors, 2)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if results[0].Error != nil {
		t.Errorf("index 0 error: %v", results[0].Error)
	}
	if results[1].Error != nil {
		t.Errorf("index 1 error: %v", results[1].Error)
	}
	if results[2].Error == nil {
		t.Error("expected error for invalid vector")
	}
}

func TestBatchParse_Empty(t *testing.T) {
	results := BatchParse(nil, 4)
	if results != nil {
		t.Error("expected nil for empty input")
	}
}

func TestBatchValidate(t *testing.T) {
	vectors := []string{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.1/AV:N/AC:L",
	}
	results := BatchValidate(vectors, 2)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if !results[0].Valid {
		t.Error("index 0 should be valid")
	}
	if results[1].Valid {
		t.Error("index 1 should be invalid")
	}
}

func TestBatchValidate_Empty(t *testing.T) {
	results := BatchValidate(nil, 4)
	if results != nil {
		t.Error("expected nil for empty input")
	}
}
