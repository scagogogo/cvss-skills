package cvss

import (
	"strings"
	"testing"
)

// ==================== Version Conversion Tests ====================

func TestConvertToVersion(t *testing.T) {
	cv := CriticalV31()

	v30, err := cv.ConvertToVersion(3, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !v30.Is30() {
		t.Error("expected v3.0")
	}

	// Back to v3.1
	v31, err := v30.ConvertToVersion(3, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !v31.Is31() {
		t.Error("expected v3.1")
	}
}

func TestConvertToVersion_Invalid(t *testing.T) {
	cv := CriticalV31()
	_, err := cv.ConvertToVersion(2, 0)
	if err == nil {
		t.Error("expected error for version 2.0")
	}
	_, err = cv.ConvertToVersion(3, 2)
	if err == nil {
		t.Error("expected error for version 3.2")
	}
}

func TestUpgradeTo31(t *testing.T) {
	cv, _ := NewCvss3xWithOptions(WithVersion30(), WithCriticalBase())
	upgraded, err := cv.UpgradeTo31()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !upgraded.Is31() {
		t.Error("expected v3.1")
	}
}

func TestDowngradeTo30(t *testing.T) {
	cv := CriticalV31()
	downgraded, err := cv.DowngradeTo30()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !downgraded.Is30() {
		t.Error("expected v3.0")
	}
}

// ==================== Metric Groups Tests ====================

func TestGetMetricGroups(t *testing.T) {
	cv := CriticalV31()
	groups := cv.GetMetricGroups()
	if len(groups) != 1 { // only base
		t.Errorf("expected 1 group, got %d", len(groups))
	}
	if groups[0].Name != "Base" {
		t.Errorf("expected Base, got %s", groups[0].Name)
	}
	if len(groups[0].Metrics) != 8 {
		t.Errorf("expected 8 base metrics, got %d", len(groups[0].Metrics))
	}
}

func TestGetMetricGroups_WithTemporal(t *testing.T) {
	cv, _ := NewCvss3xWithOptions(WithVersion31(), WithCriticalBase(), WithTemporal('F', 'T', 'C'))
	groups := cv.GetMetricGroups()
	if len(groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(groups))
	}
	if groups[1].Name != "Temporal" {
		t.Errorf("expected Temporal, got %s", groups[1].Name)
	}
}

func TestGetMetricGroups_WithEnvironmental(t *testing.T) {
	cv, _ := NewCvss3xWithOptions(
		WithVersion31(), WithCriticalBase(),
		WithTemporal('F', 'T', 'C'),
		WithCR('H'), WithIR('M'), WithAR('L'),
		WithMAV('N'), WithMAC('L'),
	)
	groups := cv.GetMetricGroups()
	if len(groups) != 3 {
		t.Errorf("expected 3 groups, got %d", len(groups))
	}
	if groups[2].Name != "Environmental" {
		t.Errorf("expected Environmental, got %s", groups[2].Name)
	}
}

func TestGetMetricGroups_Nil(t *testing.T) {
	var cv *Cvss3x
	groups := cv.GetMetricGroups()
	if groups != nil {
		t.Error("expected nil for nil Cvss3x")
	}
}

// ==================== Vector String By Group Tests ====================

func TestGetBaseVectorString(t *testing.T) {
	cv, _ := NewCvss3xWithOptions(WithVersion31(), WithCriticalBase(), WithTemporal('F', 'T', 'C'))
	baseStr := cv.GetBaseVectorString()
	if strings.Contains(baseStr, "/E:") {
		t.Errorf("base string should not contain temporal metrics: %s", baseStr)
	}
	if !strings.HasPrefix(baseStr, "CVSS:3.1/") {
		t.Errorf("expected CVSS prefix: %s", baseStr)
	}
}

func TestGetTemporalVectorString(t *testing.T) {
	cv, _ := NewCvss3xWithOptions(WithVersion31(), WithCriticalBase(), WithTemporal('F', 'T', 'C'))
	tempStr := cv.GetTemporalVectorString()
	if !strings.Contains(tempStr, "/E:F") {
		t.Errorf("temporal string should contain E:F: %s", tempStr)
	}
}

// ==================== Generic Accessor Tests ====================

func TestGetMetricValue(t *testing.T) {
	cv := CriticalV31()

	shortVal, longVal, err := cv.GetMetricValue("AV")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if shortVal != 'N' {
		t.Errorf("expected 'N', got '%c'", shortVal)
	}
	if longVal != "Network" {
		t.Errorf("expected Network, got %s", longVal)
	}
}

func TestGetMetricValue_Unknown(t *testing.T) {
	cv := CriticalV31()
	_, _, err := cv.GetMetricValue("ZZ")
	if err == nil {
		t.Error("expected error for unknown metric")
	}
}

func TestSetMetricValue(t *testing.T) {
	cv := CriticalV31()

	modified, err := cv.SetMetricValue("AV", 'L')
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Original unchanged
	shortVal, _, _ := cv.GetMetricValue("AV")
	if shortVal != 'N' {
		t.Error("original should not be modified")
	}
	// Modified
	shortVal, longVal, _ := modified.GetMetricValue("AV")
	if shortVal != 'L' {
		t.Errorf("expected 'L', got '%c'", shortVal)
	}
	if longVal != "Local" {
		t.Errorf("expected Local, got %s", longVal)
	}
}

func TestSetMetricValue_Temporal(t *testing.T) {
	cv := CriticalV31() // base only

	modified, err := cv.SetMetricValue("E", 'F')
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !modified.HasTemporalMetrics() {
		t.Error("modified should have temporal metrics")
	}
	// Original unchanged
	if cv.HasTemporalMetrics() {
		t.Error("original should not have temporal metrics")
	}
}

func TestSetMetricValue_Environmental(t *testing.T) {
	cv := CriticalV31()

	modified, err := cv.SetMetricValue("CR", 'H')
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !modified.HasEnvironmentalMetrics() {
		t.Error("modified should have environmental metrics")
	}
}

func TestSetMetricValue_Invalid(t *testing.T) {
	cv := CriticalV31()
	_, err := cv.SetMetricValue("AV", 'Z')
	if err == nil {
		t.Error("expected error for invalid value")
	}
	_, err = cv.SetMetricValue("ZZ", 'N')
	if err == nil {
		t.Error("expected error for unknown metric")
	}
}

// ==================== Conversion Round-Trip ====================

func TestConversion_RoundTrip(t *testing.T) {
	cv := CriticalV31()

	// v3.1 → v3.0 → v3.1
	v30, _ := cv.DowngradeTo30()
	v31, _ := v30.UpgradeTo31()

	// Same metrics, different version object
	if cv.String()[:8] != "CVSS:3.1" {
		t.Error("original should be v3.1")
	}
	if v30.String()[:8] != "CVSS:3.0" {
		t.Error("downgraded should be v3.0")
	}
	if v31.String()[:8] != "CVSS:3.1" {
		t.Error("upgraded should be v3.1")
	}

	// Same metric values (just version different)
	cvNoVersion := cv.String()[8:]
	v31NoVersion := v31.String()[8:]
	if cvNoVersion != v31NoVersion {
		t.Errorf("metrics should match after round-trip: %s vs %s", cvNoVersion, v31NoVersion)
	}
}
