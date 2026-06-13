package cvss

import (
	"encoding/json"
	"encoding/xml"
	"testing"
)

// ==================== Functional Options Tests ====================

func TestNewCvss3xWithOptions_Basic(t *testing.T) {
	cv, err := NewCvss3xWithOptions(
		WithVersion(3, 1),
		WithAV('N'), WithAC('L'), WithPR('N'), WithUI('N'),
		WithS('U'), WithC('H'), WithI('H'), WithA('H'),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cv.Is31() {
		t.Error("expected version 3.1")
	}
	if cv.Cvss3xBase.AttackVector.GetShortValue() != 'N' {
		t.Error("AV should be N")
	}
	expected := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	if cv.String() != expected {
		t.Errorf("expected %s, got %s", expected, cv.String())
	}
}

func TestNewCvss3xWithOptions_WithTemporal(t *testing.T) {
	cv, err := NewCvss3xWithOptions(
		WithVersion31(),
		WithAV('N'), WithAC('L'), WithPR('N'), WithUI('N'),
		WithS('U'), WithC('H'), WithI('H'), WithA('H'),
		WithE('F'), WithRL('T'), WithRC('C'),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cv.HasTemporalMetrics() {
		t.Error("should have temporal metrics")
	}
}

func TestNewCvss3xWithOptions_WithTemporalCombined(t *testing.T) {
	cv, err := NewCvss3xWithOptions(
		WithVersion31(),
		WithAV('N'), WithAC('L'), WithPR('N'), WithUI('N'),
		WithS('U'), WithC('H'), WithI('H'), WithA('H'),
		WithTemporal('F', 'T', 'C'),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cv.HasTemporalMetrics() {
		t.Error("should have temporal metrics")
	}
	if cv.Cvss3xTemporal.ExploitCodeMaturity.GetShortValue() != 'F' {
		t.Error("E should be F")
	}
}

func TestNewCvss3xWithOptions_WithEnvironmental(t *testing.T) {
	cv, err := NewCvss3xWithOptions(
		WithVersion31(),
		WithAV('N'), WithAC('L'), WithPR('N'), WithUI('N'),
		WithS('U'), WithC('H'), WithI('H'), WithA('H'),
		WithCR('H'), WithIR('M'), WithAR('L'),
		WithMAV('N'), WithMAC('L'), WithMPR('N'), WithMUI('N'),
		WithMS('U'), WithMC('H'), WithMI('H'), WithMA('H'),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cv.HasEnvironmentalMetrics() {
		t.Error("should have environmental metrics")
	}
}

func TestNewCvss3xWithOptions_WithRequirements(t *testing.T) {
	cv, err := NewCvss3xWithOptions(
		WithVersion31(),
		WithAV('N'), WithAC('L'), WithPR('N'), WithUI('N'),
		WithS('U'), WithC('H'), WithI('H'), WithA('H'),
		WithRequirements('H', 'M', 'L'),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cv.HasEnvironmentalMetrics() {
		t.Error("should have environmental metrics")
	}
	if cv.Cvss3xEnvironmental.ConfidentialityRequirement.GetShortValue() != 'H' {
		t.Error("CR should be H")
	}
}

func TestNewCvss3xWithOptions_InvalidValue(t *testing.T) {
	_, err := NewCvss3xWithOptions(
		WithVersion(3, 1),
		WithAV('Z'), // invalid
	)
	if err == nil {
		t.Error("expected error for invalid AV value")
	}
}

func TestNewCvss3xWithOptions_WithCriticalBase(t *testing.T) {
	cv, err := NewCvss3xWithOptions(WithVersion31(), WithCriticalBase())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	calc := NewCalculator(cv)
	score, err := calc.Calculate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if score != 10.0 {
		t.Errorf("expected 10.0, got %.1f", score)
	}
}

func TestNewCvss3xWithOptions_WithHighBase(t *testing.T) {
	cv, err := NewCvss3xWithOptions(WithVersion31(), WithHighBase())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	calc := NewCalculator(cv)
	score, _ := calc.Calculate()
	if score < 7.0 {
		t.Errorf("expected at least High range (>=7.0), got %.1f", score)
	}
}

func TestNewCvss3xWithOptions_WithMediumBase(t *testing.T) {
	cv, err := NewCvss3xWithOptions(WithVersion31(), WithMediumBase())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	calc := NewCalculator(cv)
	score, _ := calc.Calculate()
	if score < 4.0 || score >= 7.0 {
		t.Errorf("expected Medium range (4.0-6.9), got %.1f", score)
	}
}

func TestNewCvss3xWithOptions_WithLowBase(t *testing.T) {
	cv, err := NewCvss3xWithOptions(WithVersion31(), WithLowBase())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	calc := NewCalculator(cv)
	score, _ := calc.Calculate()
	if score < 0.1 || score >= 4.0 {
		t.Errorf("expected Low range (0.1-3.9), got %.1f", score)
	}
}

func TestNewCvss3xWithOptions_WithNoneBase(t *testing.T) {
	cv, err := NewCvss3xWithOptions(WithVersion31(), WithNoneBase())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	calc := NewCalculator(cv)
	score, _ := calc.Calculate()
	if score != 0.0 {
		t.Errorf("expected 0.0, got %.1f", score)
	}
}

func TestMustNewCvss3xWithOptions_Success(t *testing.T) {
	cv := MustNewCvss3xWithOptions(WithVersion31(), WithCriticalBase())
	if cv == nil {
		t.Error("expected non-nil result")
	}
}

func TestMustNewCvss3xWithOptions_Panic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic")
		}
	}()
	MustNewCvss3xWithOptions(WithAV('Z'))
}

func TestNewCvss3xWithOptions_DefaultVersion(t *testing.T) {
	cv, err := NewCvss3xWithOptions(WithAV('N'), WithAC('L'), WithPR('N'), WithUI('N'),
		WithS('U'), WithC('H'), WithI('H'), WithA('H'))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cv.Is31() {
		t.Error("default version should be 3.1")
	}
}

func TestNewCvss3xWithOptions_Version30(t *testing.T) {
	cv, err := NewCvss3xWithOptions(WithVersion30(), WithAV('N'), WithAC('L'), WithPR('N'), WithUI('N'),
		WithS('U'), WithC('H'), WithI('H'), WithA('H'))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cv.Is30() {
		t.Error("expected version 3.0")
	}
}

// ==================== With* Method Tests ====================

func TestCvss3x_WithAVMethod(t *testing.T) {
	original := CriticalV31()
	modified, err := original.WithAVMethod('L')
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Original unchanged
	if original.Cvss3xBase.AttackVector.GetShortValue() != 'N' {
		t.Error("original should be unchanged")
	}
	// Modified has new value
	if modified.Cvss3xBase.AttackVector.GetShortValue() != 'L' {
		t.Error("modified should have AV:L")
	}
}

func TestCvss3x_WithSMethod(t *testing.T) {
	cv := HighV31()
	modified, err := cv.WithSMethod('C')
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if modified.Cvss3xBase.Scope.GetShortValue() != 'C' {
		t.Error("scope should be Changed")
	}
	if cv.Cvss3xBase.Scope.GetShortValue() != 'U' {
		t.Error("original scope should be Unchanged")
	}
}

func TestCvss3x_WithTemporalMethod(t *testing.T) {
	cv := CriticalV31()
	modified, err := cv.WithTemporalMethod('F', 'T', 'C')
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !modified.HasTemporalMetrics() {
		t.Error("should have temporal metrics")
	}
	if cv.HasTemporalMetrics() {
		t.Error("original should not have temporal metrics but does - mutation leaked")
	}
}

func TestCvss3x_WithEMethod(t *testing.T) {
	cv := HighV31()
	modified, err := cv.WithEMethod('U')
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if modified.Cvss3xTemporal.ExploitCodeMaturity.GetShortValue() != 'U' {
		t.Error("E should be U")
	}
}

func TestCvss3x_WithCRMethod(t *testing.T) {
	cv := CriticalV31()
	modified, err := cv.WithCRMethod('H')
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !modified.HasEnvironmentalMetrics() {
		t.Error("should have environmental metrics")
	}
}

func TestCvss3x_WithVersionMethod(t *testing.T) {
	cv := CriticalV31()
	modified, err := cv.WithVersionMethod(3, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !modified.Is30() {
		t.Error("should be version 3.0")
	}
	if !cv.Is31() {
		t.Error("original should remain 3.1")
	}
}

func TestCvss3x_WithMethod_InvalidValue(t *testing.T) {
	cv := CriticalV31()
	_, err := cv.WithAVMethod('Z')
	if err == nil {
		t.Error("expected error for invalid value")
	}
}

func TestCvss3x_WithMethod_AllBaseMetrics(t *testing.T) {
	cv := NoneV31()
	modified, err := cv.WithAVMethod('N')
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	modified, err = modified.WithACMethod('L')
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	modified, err = modified.WithPRMethod('N')
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	modified, err = modified.WithUIMethod('N')
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	modified, err = modified.WithSMethod('C')
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	modified, err = modified.WithCMethod('H')
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	modified, err = modified.WithIMethod('H')
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	modified, err = modified.WithAMethod('H')
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
	if modified.String() != expected {
		t.Errorf("expected %s, got %s", expected, modified.String())
	}
}

// ==================== FromMap Tests ====================

func TestFromMap_Basic(t *testing.T) {
	cv, err := FromMap(map[string]string{
		"version": "3.1",
		"AV": "N", "AC": "L", "PR": "N", "UI": "N",
		"S": "U", "C": "H", "I": "H", "A": "H",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	if cv.String() != expected {
		t.Errorf("expected %s, got %s", expected, cv.String())
	}
}

func TestFromMap_WithTemporal(t *testing.T) {
	cv, err := FromMap(map[string]string{
		"version": "3.1",
		"AV": "N", "AC": "L", "PR": "N", "UI": "N",
		"S": "U", "C": "H", "I": "H", "A": "H",
		"E": "F", "RL": "T", "RC": "C",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cv.HasTemporalMetrics() {
		t.Error("should have temporal metrics")
	}
}

func TestFromMap_WithEnvironmental(t *testing.T) {
	cv, err := FromMap(map[string]string{
		"version": "3.1",
		"AV": "N", "AC": "L", "PR": "N", "UI": "N",
		"S": "U", "C": "H", "I": "H", "A": "H",
		"CR": "H", "IR": "M", "AR": "L",
		"MAV": "N", "MAC": "L", "MPR": "N", "MUI": "N",
		"MS": "U", "MC": "H", "MI": "H", "MA": "H",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cv.HasEnvironmentalMetrics() {
		t.Error("should have environmental metrics")
	}
}

func TestFromMap_DefaultVersion(t *testing.T) {
	cv, err := FromMap(map[string]string{
		"AV": "N", "AC": "L", "PR": "N", "UI": "N",
		"S": "U", "C": "H", "I": "H", "A": "H",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cv.Is31() {
		t.Error("default version should be 3.1")
	}
}

func TestFromMap_Version30(t *testing.T) {
	cv, err := FromMap(map[string]string{
		"version": "3.0",
		"AV": "N", "AC": "L", "PR": "N", "UI": "N",
		"S": "U", "C": "H", "I": "H", "A": "H",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cv.Is30() {
		t.Error("expected version 3.0")
	}
}

func TestFromMap_Nil(t *testing.T) {
	_, err := FromMap(nil)
	if err == nil {
		t.Error("expected error for nil map")
	}
}

func TestFromMap_InvalidValue(t *testing.T) {
	_, err := FromMap(map[string]string{
		"version": "3.1",
		"AV": "Z",
	})
	if err == nil {
		t.Error("expected error for invalid AV value")
	}
}

func TestMustFromMap_Panic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic")
		}
	}()
	MustFromMap(nil)
}

func TestCvss3x_ToMap(t *testing.T) {
	cv := CriticalV31()
	m := cv.ToMap()
	if m["version"] != "3.1" {
		t.Errorf("expected version 3.1, got %s", m["version"])
	}
	if m["AV"] != "N" {
		t.Errorf("expected AV=N, got %s", m["AV"])
	}
	if m["S"] != "C" {
		t.Errorf("expected S=C, got %s", m["S"])
	}
}

func TestCvss3x_ToMap_WithTemporal(t *testing.T) {
	cv, _ := NewCvss3xWithOptions(WithVersion31(), WithCriticalBase(), WithTemporal('F', 'T', 'C'))
	m := cv.ToMap()
	if m["E"] != "F" {
		t.Errorf("expected E=F, got %s", m["E"])
	}
	if m["RL"] != "T" {
		t.Errorf("expected RL=T, got %s", m["RL"])
	}
}

func TestCvss3x_ToMap_Nil(t *testing.T) {
	var cv *Cvss3x
	m := cv.ToMap()
	if m != nil {
		t.Error("expected nil map for nil Cvss3x")
	}
}

// ==================== FromVectorValues Tests ====================

func TestFromVectorValues_Basic(t *testing.T) {
	cv, err := FromVectorValues("3.1", "AV:N", "AC:L", "PR:N", "UI:N", "S:U", "C:H", "I:H", "A:H")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	if cv.String() != expected {
		t.Errorf("expected %s, got %s", expected, cv.String())
	}
}

func TestFromVectorValues_Empty(t *testing.T) {
	_, err := FromVectorValues("3.1")
	if err == nil {
		t.Error("expected error for empty pairs")
	}
}

// ==================== Distance Checked Tests ====================

func TestDistanceChecked_Euclidean(t *testing.T) {
	cv1 := CriticalV31()
	cv2 := HighV31()
	dc := NewDistanceCalculator(cv1, cv2)

	dist, err := dc.EuclideanDistanceChecked()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dist <= 0 {
		t.Error("expected positive distance")
	}
}

func TestDistanceChecked_IncompleteBase(t *testing.T) {
	cv1 := &Cvss3x{Cvss3xBase: &Cvss3xBase{}}
	cv2 := CriticalV31()
	dc := NewDistanceCalculator(cv1, cv2)

	_, err := dc.EuclideanDistanceChecked()
	if err == nil {
		t.Error("expected error for incomplete base metrics")
	}
}

func TestDistanceChecked_Manhattan(t *testing.T) {
	cv1 := CriticalV31()
	cv2 := HighV31()
	dc := NewDistanceCalculator(cv1, cv2)

	dist, err := dc.ManhattanDistanceChecked()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dist <= 0 {
		t.Error("expected positive distance")
	}
}

func TestDistanceChecked_ScoreDifference(t *testing.T) {
	cv1 := CriticalV31()
	cv2 := HighV31()
	dc := NewDistanceCalculator(cv1, cv2)

	diff, err := dc.ScoreDifferenceChecked()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff <= 0 {
		t.Error("expected positive score difference")
	}
}

func TestDistanceChecked_ScoreDifference_NilVector(t *testing.T) {
	dc := NewDistanceCalculator(nil, CriticalV31())
	_, err := dc.ScoreDifferenceChecked()
	if err == nil {
		t.Error("expected error for nil vector")
	}
}

func TestDistanceChecked_EuclideanWithEnv(t *testing.T) {
	cv1, _ := NewCvss3xWithOptions(WithVersion31(), WithCriticalBase(),
		WithCR('H'), WithIR('H'), WithAR('H'),
		WithMAV('N'), WithMAC('L'), WithMPR('N'), WithMUI('N'),
		WithMS('C'), WithMC('H'), WithMI('H'), WithMA('H'))
	cv2, _ := NewCvss3xWithOptions(WithVersion31(), WithHighBase(),
		WithCR('L'), WithIR('L'), WithAR('L'),
		WithMAV('A'), WithMAC('H'), WithMPR('L'), WithMUI('R'),
		WithMS('U'), WithMC('L'), WithMI('L'), WithMA('L'))
	dc := NewDistanceCalculator(cv1, cv2)

	dist, err := dc.EuclideanDistanceWithEnvChecked()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dist <= 0 {
		t.Error("expected positive distance")
	}
}

// ==================== Builder BuildChecked Tests ====================

func TestBuilder_BuildChecked_Complete(t *testing.T) {
	cv, err := NewBuilder().Version(3, 1).
		AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').
		BuildChecked()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cv == nil {
		t.Error("expected non-nil result")
	}
}

func TestBuilder_BuildChecked_Incomplete(t *testing.T) {
	_, err := NewBuilder().Version(3, 1).
		AV('N').AC('L'). // missing PR, UI, S, C, I, A
		BuildChecked()
	if err == nil {
		t.Error("expected error for incomplete base metrics")
	}
}

func TestBuilder_BuildChecked_InvalidVersion(t *testing.T) {
	_, err := NewBuilder().Version(4, 0).
		AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').
		BuildChecked()
	if err == nil {
		t.Error("expected error for invalid version")
	}
}

// ==================== TextMarshaler/TextUnmarshaler Tests ====================

func TestCvss3x_MarshalText(t *testing.T) {
	cv := CriticalV31()
	text, err := cv.MarshalText()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
	if string(text) != expected {
		t.Errorf("expected %s, got %s", expected, string(text))
	}
}

func TestCvss3x_MarshalText_Nil(t *testing.T) {
	var cv *Cvss3x
	text, err := cv.MarshalText()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if text != nil {
		t.Errorf("expected nil, got %s", string(text))
	}
}

func TestCvss3x_UnmarshalText(t *testing.T) {
	var cv Cvss3x
	err := cv.UnmarshalText([]byte("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cv.Is31() {
		t.Error("expected version 3.1")
	}
}

func TestCvss3x_UnmarshalText_Empty(t *testing.T) {
	var cv Cvss3x
	err := cv.UnmarshalText([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error for empty input: %v", err)
	}
}

func TestCvss3x_UnmarshalText_Invalid(t *testing.T) {
	var cv Cvss3x
	err := cv.UnmarshalText([]byte("invalid"))
	if err == nil {
		t.Error("expected error for invalid text")
	}
}

func TestCvss3x_XMLRoundTrip(t *testing.T) {
	type Vulnerability struct {
		XMLName xml.Name `xml:"vulnerability"`
		CVSS    *Cvss3x  `xml:"cvss"`
	}

	cv := CriticalV31()
	v := &Vulnerability{CVSS: cv}

	data, err := xml.Marshal(v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var v2 Vulnerability
	err = xml.Unmarshal(data, &v2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if v2.CVSS.String() != cv.String() {
		t.Errorf("round-trip failed: expected %s, got %s", cv.String(), v2.CVSS.String())
	}
}

func TestCvss3x_JSONRoundTrip_WithTextMarshaler(t *testing.T) {
	type Wrapper struct {
		CVSS *Cvss3x `json:"cvss"`
	}

	cv := CriticalV31()
	w := &Wrapper{CVSS: cv}

	data, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var w2 Wrapper
	err = json.Unmarshal(data, &w2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if w2.CVSS.String() != cv.String() {
		t.Errorf("round-trip failed: expected %s, got %s", cv.String(), w2.CVSS.String())
	}
}

// ==================== Presets Tests ====================

func TestCriticalV31(t *testing.T) {
	cv := CriticalV31()
	calc := NewCalculator(cv)
	score, _ := calc.Calculate()
	if score != 10.0 {
		t.Errorf("expected 10.0, got %.1f", score)
	}
}

func TestHighV31(t *testing.T) {
	cv := HighV31()
	calc := NewCalculator(cv)
	score, _ := calc.Calculate()
	if score < 7.0 {
		t.Errorf("expected at least High (>=7.0), got %.1f", score)
	}
}

func TestMediumV31(t *testing.T) {
	cv := MediumV31()
	calc := NewCalculator(cv)
	score, _ := calc.Calculate()
	if score < 4.0 || score >= 7.0 {
		t.Errorf("expected Medium range, got %.1f", score)
	}
}

func TestLowV31(t *testing.T) {
	cv := LowV31()
	calc := NewCalculator(cv)
	score, _ := calc.Calculate()
	if score < 0.1 || score >= 4.0 {
		t.Errorf("expected Low range, got %.1f", score)
	}
}

func TestNoneV31(t *testing.T) {
	cv := NoneV31()
	calc := NewCalculator(cv)
	score, _ := calc.Calculate()
	if score != 0.0 {
		t.Errorf("expected 0.0, got %.1f", score)
	}
}

func TestCriticalV30(t *testing.T) {
	cv := CriticalV30()
	if !cv.Is30() {
		t.Error("expected version 3.0")
	}
	calc := NewCalculator(cv)
	score, _ := calc.Calculate()
	if score != 10.0 {
		t.Errorf("expected 10.0, got %.1f", score)
	}
}

func TestHighV30(t *testing.T) {
	cv := HighV30()
	if !cv.Is30() {
		t.Error("expected version 3.0")
	}
}

func TestNoneV30(t *testing.T) {
	cv := NoneV30()
	if !cv.Is30() {
		t.Error("expected version 3.0")
	}
	calc := NewCalculator(cv)
	score, _ := calc.Calculate()
	if score != 0.0 {
		t.Errorf("expected 0.0, got %.1f", score)
	}
}

// ==================== JSON Bug Fix Tests ====================

func TestToJSON_PartialTemporal(t *testing.T) {
	// This tests the fix for the nil panic when Cvss3xTemporal exists
	// but some fields are nil
	cv, _ := NewCvss3xWithOptions(
		WithVersion31(),
		WithAV('N'), WithAC('L'), WithPR('N'), WithUI('N'),
		WithS('U'), WithC('H'), WithI('H'), WithA('H'),
	)
	cv.Cvss3xTemporal = &Cvss3xTemporal{
		ExploitCodeMaturity: nil, // nil field
		RemediationLevel:    nil, // nil field
		ReportConfidence:    nil, // nil field
	}
	// hasTemporalMetrics returns false if all fields are nil
	// so this should not output temporal in JSON
	calc := NewCalculator(cv)
	_, err := cv.ToJSON(calc)
	// Should not panic even with partial temporal
	if err != nil {
		t.Logf("ToJSON with partial temporal returned: %v (may be expected if not passing Check)", err)
	}
}

func TestToJSON_PartialTemporal_OneSet(t *testing.T) {
	cv := MustNewCvss3xWithOptions(
		WithVersion31(),
		WithAV('N'), WithAC('L'), WithPR('N'), WithUI('N'),
		WithS('U'), WithC('H'), WithI('H'), WithA('H'),
		WithE('F'), // Only E is set, RL and RC are nil
	)
	calc := NewCalculator(cv)
	_, err := cv.ToJSON(calc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should not panic with partial temporal (E set, RL/RC nil)
}

// ==================== FromJSON Error Handling Tests ====================

func TestFromJSON_MetricsWithInvalidValue(t *testing.T) {
	jsonData := `{
		"version": "3.1",
		"metrics": {
			"base": {
				"attackVector": "InvalidValue",
				"attackComplexity": "Low",
				"privilegesRequired": "None",
				"userInteraction": "None",
				"scope": "Unchanged",
				"confidentiality": "High",
				"integrity": "High",
				"availability": "High"
			}
		}
	}`
	_, err := FromJSON([]byte(jsonData))
	if err == nil {
		t.Error("expected error for invalid metric value in JSON metrics")
	}
}


