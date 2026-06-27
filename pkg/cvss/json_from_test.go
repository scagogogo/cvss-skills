package cvss

import (
	"testing"

	"github.com/scagogogo/cvss-skills/pkg/vector"
	"github.com/stretchr/testify/assert"
)

func TestFromJSON_WithVectorString(t *testing.T) {
	original := NewCvss3x()
	original.MajorVersion = 3
	original.MinorVersion = 1
	original.Cvss3xBase = &Cvss3xBase{
		AttackVector:       vector.AttackVectorNetwork,
		AttackComplexity:   vector.AttackComplexityLow,
		PrivilegesRequired: vector.PrivilegesRequiredNone,
		UserInteraction:    vector.UserInteractionNone,
		Scope:              vector.ScopeUnchanged,
		Confidentiality:    vector.ConfidentialityHigh,
		Integrity:          vector.IntegrityHigh,
		Availability:       vector.AvailabilityHigh,
	}

	calc := NewCalculator(original)
	jsonData, err := original.ToJSON(calc)
	assert.NoError(t, err)

	restored, err := FromJSON(jsonData)
	assert.NoError(t, err)
	assert.NotNil(t, restored)

	// Verify scores match
	restoredScore, err := NewCalculator(restored).Calculate()
	assert.NoError(t, err)
	originalScore, _ := calc.Calculate()
	assert.Equal(t, originalScore, restoredScore)
}

func TestFromJSON_WithTemporal(t *testing.T) {
	original := NewCvss3x()
	original.MajorVersion = 3
	original.MinorVersion = 1
	original.Cvss3xBase = &Cvss3xBase{
		AttackVector:       vector.AttackVectorNetwork,
		AttackComplexity:   vector.AttackComplexityLow,
		PrivilegesRequired: vector.PrivilegesRequiredNone,
		UserInteraction:    vector.UserInteractionNone,
		Scope:              vector.ScopeUnchanged,
		Confidentiality:    vector.ConfidentialityHigh,
		Integrity:          vector.IntegrityHigh,
		Availability:       vector.AvailabilityHigh,
	}
	original.Cvss3xTemporal = &Cvss3xTemporal{
		ExploitCodeMaturity: vector.ExploitCodeMaturityHigh,
		RemediationLevel:    vector.RemediationLevelUnavailable,
		ReportConfidence:    vector.ReportConfidenceConfirmed,
	}

	calc := NewCalculator(original)
	jsonData, err := original.ToJSON(calc)
	assert.NoError(t, err)

	restored, err := FromJSON(jsonData)
	assert.NoError(t, err)
	assert.NotNil(t, restored.Cvss3xTemporal)
}

func TestFromJSON_InvalidJSON(t *testing.T) {
	_, err := FromJSON([]byte("not json"))
	assert.Error(t, err)
}

func TestFromJSON_MissingMetrics(t *testing.T) {
	_, err := FromJSON([]byte(`{"version":"3.1","vectorString":"","baseScore":9.8}`))
	assert.Error(t, err)
}

func TestFromJSON_RoundTrip(t *testing.T) {
	// Test that ToJSON → FromJSON produces the same scores
	original := NewCvss3x()
	original.MajorVersion = 3
	original.MinorVersion = 1
	original.Cvss3xBase = &Cvss3xBase{
		AttackVector:       vector.AttackVectorLocal,
		AttackComplexity:   vector.AttackComplexityHigh,
		PrivilegesRequired: vector.PrivilegesRequiredLow,
		UserInteraction:    vector.UserInteractionRequired,
		Scope:              vector.ScopeChanged,
		Confidentiality:    vector.ConfidentialityLow,
		Integrity:          vector.IntegrityLow,
		Availability:       vector.AvailabilityNone,
	}

	calc := NewCalculator(original)
	jsonData, err := original.ToJSON(calc)
	assert.NoError(t, err)

	restored, err := FromJSON(jsonData)
	assert.NoError(t, err)

	// Vector string should match
	assert.Equal(t, original.String(), restored.String())
}
