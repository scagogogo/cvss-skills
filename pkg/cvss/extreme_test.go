package cvss

import (
	"encoding/json"
	"testing"

	"github.com/scagogogo/cvss-parser/pkg/vector"
	"github.com/stretchr/testify/assert"
)

// ==================== validate.go tests ====================

func TestValidate_AllMissing(t *testing.T) {
	cv := NewCvss3x()
	err := cv.Validate()
	assert.Error(t, err)

	var ve ValidationErrors
	assert.ErrorAs(t, err, &ve)
	// Should report all 8 base metrics + version
	assert.GreaterOrEqual(t, len(ve), 8)
}

func TestValidate_Partial(t *testing.T) {
	cv := NewCvss3x()
	cv.MajorVersion = 3
	cv.MinorVersion = 1
	cv.Cvss3xBase.AttackVector = vector.AttackVectorNetwork
	cv.Cvss3xBase.AttackComplexity = vector.AttackComplexityLow
	// Missing: PR, UI, S, C, I, A

	err := cv.Validate()
	assert.Error(t, err)

	var ve ValidationErrors
	assert.ErrorAs(t, err, &ve)
	missing := ve.MissingMetrics()
	assert.Contains(t, missing, "PR")
	assert.Contains(t, missing, "UI")
	assert.Contains(t, missing, "S")
	assert.Contains(t, missing, "C")
	assert.Contains(t, missing, "I")
	assert.Contains(t, missing, "A")
	// AV and AC should NOT be in missing
	assert.NotContains(t, missing, "AV")
	assert.NotContains(t, missing, "AC")
}

func TestValidate_Valid(t *testing.T) {
	cv := NewBuilder().Version(3, 1).AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').MustBuild()
	err := cv.Validate()
	assert.NoError(t, err)
}

func TestMissingMetrics(t *testing.T) {
	cv := NewCvss3x()
	cv.MajorVersion = 3
	cv.MinorVersion = 1
	cv.Cvss3xBase.AttackVector = vector.AttackVectorNetwork
	missing := cv.MissingMetrics()
	assert.Contains(t, missing, "AC")
	assert.Contains(t, missing, "PR")
	assert.NotContains(t, missing, "AV")
}

func TestValidationError_Error(t *testing.T) {
	ve := ValidationErrors{
		{Metric: "AV", Message: "is required but not set"},
		{Metric: "PR", Message: "is required but not set"},
	}
	errStr := ve.Error()
	assert.Contains(t, errStr, "AV")
	assert.Contains(t, errStr, "PR")
	assert.True(t, ve.HasErrors())
}

// ==================== builder.go tests ====================

func TestBuilder_BaseOnly(t *testing.T) {
	cv, err := NewBuilder().Version(3, 1).AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').Build()
	assert.NoError(t, err)
	assert.Equal(t, 3, cv.MajorVersion)
	assert.Equal(t, 1, cv.MinorVersion)
	assert.NotNil(t, cv.Cvss3xBase)
	assert.Nil(t, cv.Cvss3xTemporal)
	assert.Nil(t, cv.Cvss3xEnvironmental)

	score, err := NewCalculator(cv).Calculate()
	assert.NoError(t, err)
	assert.Equal(t, 9.8, score)
}

func TestBuilder_WithTemporal(t *testing.T) {
	cv, err := NewBuilder().Version(3, 1).
		AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').
		E('U').RL('O').RC('C').Build()
	assert.NoError(t, err)
	assert.NotNil(t, cv.Cvss3xTemporal)
}

func TestBuilder_InvalidValue(t *testing.T) {
	_, err := NewBuilder().Version(3, 1).AV('Z').Build()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "AV")
}

func TestBuilder_MustBuild_Panic(t *testing.T) {
	assert.Panics(t, func() {
		NewBuilder().AV('Z').MustBuild()
	})
}

// ==================== diff.go tests ====================

func TestDiff_Identical(t *testing.T) {
	cv1 := NewBuilder().Version(3, 1).AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').MustBuild()
	cv2 := NewBuilder().Version(3, 1).AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').MustBuild()
	diffs := cv1.Diff(cv2)
	assert.Empty(t, diffs)
}

func TestDiff_DifferentValues(t *testing.T) {
	cv1 := NewBuilder().Version(3, 1).AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').MustBuild()
	cv2 := NewBuilder().Version(3, 1).AV('L').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').MustBuild()
	diffs := cv1.Diff(cv2)
	assert.Len(t, diffs, 1)
	assert.Equal(t, "AV", diffs[0].Metric)
	assert.Equal(t, "N", diffs[0].V1)
	assert.Equal(t, "L", diffs[0].V2)
}

func TestDiff_MultipleDifferences(t *testing.T) {
	cv1 := NewBuilder().Version(3, 1).AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').MustBuild()
	cv2 := NewBuilder().Version(3, 1).AV('L').AC('H').PR('N').UI('N').S('U').C('H').I('H').A('H').MustBuild()
	diffs := cv1.Diff(cv2)
	assert.Len(t, diffs, 2)
}

func TestDiffEntry_String(t *testing.T) {
	d := DiffEntry{Metric: "AV", V1: "N", V2: "L"}
	assert.Equal(t, "AV: N vs L", d.String())
}

func TestMerge(t *testing.T) {
	base := NewBuilder().Version(3, 1).AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').MustBuild()
	overlay := &Cvss3x{
		Cvss3xTemporal: &Cvss3xTemporal{
			ExploitCodeMaturity: vector.ExploitCodeMaturityHigh,
		},
	}

	merged := base.Merge(overlay)
	assert.NotNil(t, merged.Cvss3xTemporal)
	assert.Equal(t, vector.ExploitCodeMaturityHigh, merged.Cvss3xTemporal.ExploitCodeMaturity)
	// Base metrics should be preserved
	assert.Equal(t, vector.AttackVectorNetwork, merged.Cvss3xBase.AttackVector)
	// Original should not be modified
	assert.Nil(t, base.Cvss3xTemporal)
}

func TestMerge_DoesNotOverwrite(t *testing.T) {
	cv1 := NewBuilder().Version(3, 1).AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').MustBuild()
	cv2 := NewBuilder().Version(3, 1).AV('L').AC('H').PR('H').UI('R').S('C').C('L').I('L').A('N').MustBuild()

	merged := cv1.Merge(cv2)
	// cv1's values should be preserved (not overwritten)
	assert.Equal(t, vector.AttackVectorNetwork, merged.Cvss3xBase.AttackVector)
}

func TestDescription(t *testing.T) {
	cv := NewBuilder().Version(3, 1).AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').MustBuild()
	desc := cv.Description()
	assert.Contains(t, desc, "Attack Vector: Network")
	assert.Contains(t, desc, "Attack Complexity: Low")
	assert.Contains(t, desc, "Confidentiality: High")
}

// ==================== severity.go tests ====================

func TestSeverity_IsNone(t *testing.T) {
	assert.True(t, SeverityNone.IsNone())
	assert.False(t, SeverityLow.IsNone())
}

func TestSeverity_IsLow(t *testing.T) {
	assert.True(t, SeverityLow.IsLow())
	assert.False(t, SeverityMedium.IsLow())
}

func TestSeverity_IsMedium(t *testing.T) {
	assert.True(t, SeverityMedium.IsMedium())
	assert.False(t, SeverityHigh.IsMedium())
}

func TestSeverity_IsHigh(t *testing.T) {
	assert.True(t, SeverityHigh.IsHigh())
	assert.False(t, SeverityCritical.IsHigh())
}

func TestSeverity_IsCritical(t *testing.T) {
	assert.True(t, SeverityCritical.IsCritical())
	assert.False(t, SeverityHigh.IsCritical())
}

// ==================== scores.go tests ====================

func TestAllScores_String(t *testing.T) {
	cv := NewBuilder().Version(3, 1).AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').MustBuild()
	calc := NewCalculator(cv)
	scores, err := calc.GetAllScores()
	assert.NoError(t, err)
	s := scores.String()
	assert.Contains(t, s, "Base: 9.8")
	assert.Contains(t, s, "Critical")
}

func TestAllScores_String_Nil(t *testing.T) {
	var scores *AllScores
	assert.Equal(t, "<nil>", scores.String())
}

// ==================== cvss3x.go MarshalJSON tests ====================

func TestCvss3x_MarshalJSON(t *testing.T) {
	cv := NewBuilder().Version(3, 1).AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').MustBuild()
	data, err := json.Marshal(cv)
	assert.NoError(t, err)
	assert.Contains(t, string(data), "CVSS:3.1")
	assert.Contains(t, string(data), "AV:N")
}

func TestCvss3x_UnmarshalJSON(t *testing.T) {
	var cv Cvss3x
	err := json.Unmarshal([]byte(`"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`), &cv)
	assert.NoError(t, err)
	assert.Equal(t, 3, cv.MajorVersion)
	assert.Equal(t, 1, cv.MinorVersion)
	assert.NotNil(t, cv.Cvss3xBase)
}

func TestCvss3x_JSON_RoundTrip(t *testing.T) {
	original := NewBuilder().Version(3, 1).AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').MustBuild()
	data, err := json.Marshal(original)
	assert.NoError(t, err)

	var restored Cvss3x
	err = json.Unmarshal(data, &restored)
	assert.NoError(t, err)

	// Vector string should be identical
	assert.Equal(t, original.String(), restored.String())
}

// ==================== roundUp spec-compliant tests ====================

func TestRoundUp_SpecCompliant(t *testing.T) {
	// Test the CVSS v3.1 spec's integer algorithm
	assert.Equal(t, 0.0, RoundUp(0.0))
	assert.Equal(t, 3.1, RoundUp(3.0089))  // 3.0089 rounds up to 3.1
	assert.Equal(t, 3.1, RoundUp(3.1))     // 3.1 is exact, stays 3.1
	assert.Equal(t, 10.0, RoundUp(9.999))
	assert.Equal(t, 7.0, RoundUp(7.0))     // 7.0 is exact, stays 7.0
	assert.Equal(t, 4.0, RoundUp(3.99))
}

// ==================== v3.0 vs v3.1 UI score ====================

func TestGetUserInteractionScore_v30(t *testing.T) {
	assert.Equal(t, 0.56, vector.GetUserInteractionScore(vector.UserInteractionRequired, 0))
	assert.Equal(t, 0.85, vector.GetUserInteractionScore(vector.UserInteractionNone, 0))
}

func TestGetUserInteractionScore_v31(t *testing.T) {
	assert.Equal(t, 0.62, vector.GetUserInteractionScore(vector.UserInteractionRequired, 1))
	assert.Equal(t, 0.85, vector.GetUserInteractionScore(vector.UserInteractionNone, 1))
}
