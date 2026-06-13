package cvss

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// ==================== Batch Operations Tests ====================

func TestBatchScore(t *testing.T) {
	v1 := CriticalV31()
	v2 := HighV31()
	v3 := NoneV31()

	results := BatchScore([]*Cvss3x{v1, v2, v3}, 2)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	if results[0].Error != nil {
		t.Errorf("index 0 error: %v", results[0].Error)
	}
	if results[0].Score != 10.0 {
		t.Errorf("index 0: expected 10.0, got %.1f", results[0].Score)
	}
	if !results[0].Severity.IsCritical() {
		t.Errorf("index 0: expected Critical, got %s", results[0].Severity)
	}

	if results[2].Score != 0.0 {
		t.Errorf("index 2: expected 0.0, got %.1f", results[2].Score)
	}
}

func TestBatchScore_Empty(t *testing.T) {
	results := BatchScore(nil, 4)
	if results != nil {
		t.Error("expected nil for empty input")
	}
}

func TestBatchScore_NilElement(t *testing.T) {
	results := BatchScore([]*Cvss3x{nil, CriticalV31()}, 1)
	if results[0].Error == nil {
		t.Error("expected error for nil element")
	}
}

func TestBatchAllScores(t *testing.T) {
	v1 := CriticalV31()
	results := BatchAllScores([]*Cvss3x{v1}, 1)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Error != nil {
		t.Errorf("unexpected error: %v", results[0].Error)
	}
	if results[0].Scores.BaseScore != 10.0 {
		t.Errorf("expected 10.0, got %.1f", results[0].Scores.BaseScore)
	}
}


// ==================== Impact Analysis Tests ====================

func TestImpactAnalysis(t *testing.T) {
	cv := CriticalV31()
	impacts, err := ImpactAnalysis(cv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(impacts) != 8 {
		t.Errorf("expected 8 metric impacts, got %d", len(impacts))
	}

	// The most impactful metric should be first
	if impacts[0].Metric == "" {
		t.Error("first impact metric should not be empty")
	}
}

func TestImpactAnalysis_Nil(t *testing.T) {
	_, err := ImpactAnalysis(nil)
	if err == nil {
		t.Error("expected error for nil")
	}
}

func TestSensitivityAnalysis(t *testing.T) {
	cv := HighV31()
	sensitivities, err := SensitivityAnalysis(cv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sensitivities) != 8 {
		t.Errorf("expected 8 sensitivities, got %d", len(sensitivities))
	}

	// ScoreSwing should be >= 0
	for _, s := range sensitivities {
		if s.ScoreSwing < 0 {
			t.Errorf("%s: negative swing %.1f", s.Metric, s.ScoreSwing)
		}
	}

	// First metric should have the largest swing
	if len(sensitivities) > 1 {
		if sensitivities[0].ScoreSwing < sensitivities[1].ScoreSwing {
			t.Error("sensitivities should be sorted by swing descending")
		}
	}
}

func TestFindMetricChangesToReachTarget(t *testing.T) {
	cv := NoneV31() // Score 0.0
	changes, err := FindMetricChangesToReachTarget(cv, 7.0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(changes) == 0 {
		t.Error("expected some changes to reach score 7.0")
	}

	// Verify the result by applying changes
	working := cv
	for _, c := range changes {
		modified, err := modifyBaseMetric(working, c.Metric, []rune(c.To)[0])
		if err != nil {
			t.Fatalf("error applying change: %v", err)
		}
		working = modified
	}
	calc := NewCalculator(working)
	finalScore, _ := calc.GetBaseScore()
	if finalScore < 7.0-0.1 {
		t.Errorf("after applying changes, score %.1f is below target 7.0", finalScore)
	}
}

// ==================== Enumeration Tests ====================

func TestListAllMetrics(t *testing.T) {
	metrics := ListAllMetrics()
	if len(metrics) < 22 {
		t.Errorf("expected at least 22 metrics, got %d", len(metrics))
	}

	// Check first metric (AV)
	if metrics[0].ShortName != "AV" {
		t.Errorf("first metric should be AV, got %s", metrics[0].ShortName)
	}
	if len(metrics[0].Values) != 4 {
		t.Errorf("AV should have 4 values, got %d", len(metrics[0].Values))
	}
}

func TestGetMetricInfo(t *testing.T) {
	info, err := GetMetricInfo("AV")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.LongName != "Attack Vector" {
		t.Errorf("expected Attack Vector, got %s", info.LongName)
	}

	_, err = GetMetricInfo("ZZ")
	if err == nil {
		t.Error("expected error for unknown metric")
	}
}

func TestGetValidValues(t *testing.T) {
	shortVals, longVals, err := GetValidValues("AV")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(shortVals) != 4 {
		t.Errorf("expected 4 values, got %d", len(shortVals))
	}
	if longVals[0] != "Network" {
		t.Errorf("first long value should be Network, got %s", longVals[0])
	}
}

func TestIsValidMetricValue(t *testing.T) {
	if !IsValidMetricValue("AV", 'N') {
		t.Error("AV:N should be valid")
	}
	if IsValidMetricValue("AV", 'Z') {
		t.Error("AV:Z should be invalid")
	}
	if IsValidMetricValue("ZZ", 'N') {
		t.Error("ZZ:N should be invalid (unknown metric)")
	}
}

func TestVectorIterator(t *testing.T) {
	iter := NewVectorIterator(1)

	total := iter.TotalCombinations()
	if total != 2592 { // 4*2*3*2*2*3*3*3
		t.Errorf("expected 2592 combinations, got %d", total)
	}

	// Count all vectors
	count := 0
	for {
		cv := iter.Next()
		if cv == nil {
			break
		}
		count++
		if !cv.Is31() {
			t.Error("expected version 3.1")
		}
	}
	if count != total {
		t.Errorf("expected %d vectors, got %d", total, count)
	}
}

func TestVectorIterator_Reset(t *testing.T) {
	iter := NewVectorIterator(1)

	// Read one
	cv1 := iter.Next()
	if cv1 == nil {
		t.Fatal("expected non-nil")
	}

	// Reset
	iter.Reset()

	// Read first again
	cv2 := iter.Next()
	if cv2 == nil {
		t.Fatal("expected non-nil after reset")
	}
	if cv2.String() != cv1.String() {
		t.Errorf("after reset, first vector should match: %s vs %s", cv1.String(), cv2.String())
	}
}

// ==================== Score Range Tests ====================

func TestGetScoreRange_Complete(t *testing.T) {
	cv := CriticalV31()
	rng := GetScoreRange(cv)
	if !rng.IsComplete {
		t.Error("should be complete")
	}
	if rng.MinScore != rng.MaxScore {
		t.Errorf("complete vector: min %.1f should equal max %.1f", rng.MinScore, rng.MaxScore)
	}
	if rng.MinScore != 10.0 {
		t.Errorf("expected 10.0, got %.1f", rng.MinScore)
	}
}

func TestGetScoreRange_Partial(t *testing.T) {
	cv, _ := NewCvss3xWithOptions(
		WithVersion31(),
		WithAV('N'), WithAC('L'), // only 2 of 8 metrics
	)
	rng := GetScoreRange(cv)
	if rng.IsComplete {
		t.Error("should not be complete")
	}
	if rng.MissingCount != 6 {
		t.Errorf("expected 6 missing, got %d", rng.MissingCount)
	}
	if rng.MaxScore < rng.MinScore {
		t.Errorf("max %.1f should be >= min %.1f", rng.MaxScore, rng.MinScore)
	}
	if rng.MinScore < 0 {
		t.Errorf("min score should be >= 0, got %.1f", rng.MinScore)
	}
	if rng.MaxScore > 10 {
		t.Errorf("max score should be <= 10, got %.1f", rng.MaxScore)
	}
}

func TestGetWorstCase(t *testing.T) {
	cv, _ := NewCvss3xWithOptions(
		WithVersion31(),
		WithAV('N'), WithAC('L'), // partial
	)
	result, score, err := GetWorstCase(cv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if score < 7.0 {
		t.Errorf("worst case for AV:N/AC:L should be high, got %.1f", score)
	}
}

func TestGetBestCase(t *testing.T) {
	cv, _ := NewCvss3xWithOptions(
		WithVersion31(),
		WithAV('N'), WithAC('L'), // partial
	)
	result, score, err := GetBestCase(cv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if score > 4.0 {
		t.Errorf("best case for partial vector should be low, got %.1f", score)
	}
}

// ==================== SQL Scanner/Valuer Tests ====================

func TestCvss3x_Scan_String(t *testing.T) {
	var cv Cvss3x
	err := cv.Scan("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cv.Is31() {
		t.Error("expected version 3.1")
	}
}

func TestCvss3x_Scan_Bytes(t *testing.T) {
	var cv Cvss3x
	err := cv.Scan([]byte("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cv.Cvss3xBase.AttackVector.GetShortValue() != 'N' {
		t.Error("AV should be N")
	}
}

func TestCvss3x_Scan_Nil(t *testing.T) {
	var cv Cvss3x
	err := cv.Scan(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCvss3x_Scan_Empty(t *testing.T) {
	var cv Cvss3x
	err := cv.Scan("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCvss3x_Scan_InvalidType(t *testing.T) {
	var cv Cvss3x
	err := cv.Scan(12345)
	if err == nil {
		t.Error("expected error for int type")
	}
}

func TestCvss3x_Value(t *testing.T) {
	cv := CriticalV31()
	val, err := cv.Value()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	str, ok := val.(string)
	if !ok {
		t.Fatal("expected string value")
	}
	if !strings.HasPrefix(str, "CVSS:3.1/") {
		t.Errorf("expected CVSS vector string, got %s", str)
	}
}

func TestCvss3x_Value_Nil(t *testing.T) {
	var cv *Cvss3x
	val, err := cv.Value()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != nil {
		t.Error("expected nil value for nil Cvss3x")
	}
}

// ==================== Sort Tests ====================

func TestCvss3xSlice_SortDesc(t *testing.T) {
	v1 := NoneV31()     // 0.0
	v2 := CriticalV31() // 10.0
	v3 := HighV31()     // 9.8
	v4 := MediumV31()   // 6.5

	slice := NewCvss3xSlice(v1, v2, v3, v4)
	slice.Sort()

	if slice.ScoreAt(0) < slice.ScoreAt(1) {
		t.Error("should be sorted descending")
	}
	if slice.ScoreAt(0) < 9.0 {
		t.Errorf("first should be highest score, got %.1f", slice.ScoreAt(0))
	}
}

func TestCvss3xSlice_SortAsc(t *testing.T) {
	v1 := CriticalV31()
	v2 := NoneV31()

	slice := NewCvss3xSlice(v1, v2)
	slice.Asc().Sort()

	if slice.ScoreAt(0) > slice.ScoreAt(1) {
		t.Error("should be sorted ascending")
	}
}

// ==================== Canonicalize Tests ====================

func TestCanonicalize(t *testing.T) {
	// Already canonical
	result, err := Canonicalize("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("expected canonical form, got %s", result)
	}
}

func TestCanonicalize_Reorder(t *testing.T) {
	// Out-of-order metrics
	result, err := Canonicalize("CVSS:3.1/S:U/C:H/I:H/A:H/AV:N/AC:L/PR:N/UI:N")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	if result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
}

func TestIsCanonical(t *testing.T) {
	if !IsCanonical("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") {
		t.Error("should be canonical")
	}
	if IsCanonical("CVSS:3.1/S:U/C:H/I:H/A:H/AV:N/AC:L/PR:N/UI:N") {
		t.Error("out-of-order should not be canonical")
	}
}

// ==================== CSV Tests ====================

func TestCSVHeader(t *testing.T) {
	header := CSVHeader()
	if len(header) < 10 {
		t.Errorf("expected at least 10 columns, got %d", len(header))
	}
	if header[0] != "vector_string" {
		t.Errorf("first column should be vector_string, got %s", header[0])
	}
}

func TestCSVRow(t *testing.T) {
	cv := CriticalV31()
	calc := NewCalculator(cv)
	row, err := cv.CSVRow(calc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(row) < 4 {
		t.Errorf("expected at least 4 columns, got %d", len(row))
	}
	if !strings.HasPrefix(row[0], "CVSS:3.1/") {
		t.Errorf("first column should be vector string, got %s", row[0])
	}
}

func TestWriteCSV(t *testing.T) {
	v1 := CriticalV31()
	v2 := NoneV31()

	var buf bytes.Buffer
	err := WriteCSV(&buf, []*Cvss3x{v1, v2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify output is valid CSV
	reader := csv.NewReader(&buf)
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("failed to read CSV: %v", err)
	}
	if len(records) != 3 { // header + 2 data rows
		t.Errorf("expected 3 records, got %d", len(records))
	}
}

func TestReadCSV(t *testing.T) {
	// Write then read
	v1 := CriticalV31()
	var buf bytes.Buffer
	WriteCSV(&buf, []*Cvss3x{v1})

	vectors, err := ReadCSV(&buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vectors) != 1 {
		t.Fatalf("expected 1 vector, got %d", len(vectors))
	}
	if vectors[0].String() != v1.String() {
		t.Errorf("expected %s, got %s", v1.String(), vectors[0].String())
	}
}

func TestReadCSVLax(t *testing.T) {
	csvContent := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\nINVALID_VECTOR\nCVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N\n"
	vectors, errors, err := ReadCSVLax(strings.NewReader(csvContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vectors) != 2 {
		t.Errorf("expected 2 valid vectors, got %d", len(vectors))
	}
	if len(errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(errors))
	}
}

// ==================== JSON Round-Trip with new types ====================

func TestJSON_RoundTrip_WithNewAPIs(t *testing.T) {
	cv, _ := NewCvss3xWithOptions(
		WithVersion31(),
		WithCriticalBase(),
		WithTemporal('F', 'T', 'C'),
	)
	data, err := json.Marshal(cv)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var cv2 Cvss3x
	err = json.Unmarshal(data, &cv2)
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if cv.String() != cv2.String() {
		t.Errorf("round-trip failed: %s vs %s", cv.String(), cv2.String())
	}
}

// ==================== Integration: All APIs together ====================

func TestIntegration_AllNewAPIs(t *testing.T) {
	// Construct via options
	cv, err := NewCvss3xWithOptions(WithVersion31(), WithCriticalBase())
	if err != nil {
		t.Fatalf("options: %v", err)
	}

	// Calculate
	calc := NewCalculator(cv)
	score, _ := calc.Calculate()
	if score != 10.0 {
		t.Fatalf("score: expected 10.0, got %.1f", score)
	}

	// Impact analysis
	impacts, err := ImpactAnalysis(cv)
	if err != nil || len(impacts) == 0 {
		t.Fatalf("impact: %v, len=%d", err, len(impacts))
	}

	// Sensitivity
	sens, err := SensitivityAnalysis(cv)
	if err != nil || len(sens) == 0 {
		t.Fatalf("sensitivity: %v, len=%d", err, len(sens))
	}

	// Modify
	modified, err := cv.WithAVMethod('L')
	if err != nil {
		t.Fatalf("with method: %v", err)
	}

	// Score range
	rng := GetScoreRange(cv)
	if !rng.IsComplete {
		t.Error("should be complete")
	}

	// SQL
	_, err = cv.Value()
	if err != nil {
		t.Fatalf("sql value: %v", err)
	}

	// CSV
	row, err := cv.CSVRow(calc)
	if err != nil || len(row) == 0 {
		t.Fatalf("csv: %v, len=%d", err, len(row))
	}

	// Sort
	slice := NewCvss3xSlice(cv, modified)
	slice.Sort()
	_ = slice.Items()

	// Canonicalize
	canonical, err := Canonicalize(cv.String())
	if err != nil || canonical == "" {
		t.Fatalf("canonicalize: %v", canonical)
	}

	// Enumerate
	metrics := ListAllMetrics()
	if len(metrics) < 22 {
		t.Errorf("expected >= 22 metrics, got %d", len(metrics))
	}

	// Batch
	batchResults := BatchScore([]*Cvss3x{cv, modified}, 2)
	if len(batchResults) != 2 {
		t.Fatalf("batch: expected 2, got %d", len(batchResults))
	}

	fmt.Printf("Integration test passed: score=%.1f, impacts=%d, sens=%d, csv_cols=%d\n",
		score, len(impacts), len(sens), len(row))
}
