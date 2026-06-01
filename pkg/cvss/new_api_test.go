package cvss

import (
	"testing"

	"github.com/scagogogo/cvss-parser/pkg/vector"
	"github.com/stretchr/testify/assert"
)

// ==================== convenience.go tests ====================

func TestCvss3x_Version(t *testing.T) {
	v30 := NewCvss3x()
	v30.MajorVersion = 3
	v30.MinorVersion = 0
	assert.Equal(t, "3.0", v30.Version())

	v31 := NewCvss3x()
	v31.MajorVersion = 3
	v31.MinorVersion = 1
	assert.Equal(t, "3.1", v31.Version())
}

func TestCvss3x_Is30_Is31(t *testing.T) {
	v30 := NewCvss3x()
	v30.MajorVersion = 3
	v30.MinorVersion = 0
	assert.True(t, v30.Is30())
	assert.False(t, v30.Is31())

	v31 := NewCvss3x()
	v31.MajorVersion = 3
	v31.MinorVersion = 1
	assert.False(t, v31.Is30())
	assert.True(t, v31.Is31())
}

func TestCvss3x_HasTemporalMetrics(t *testing.T) {
	// No temporal
	cv := NewCvss3x()
	assert.False(t, cv.HasTemporalMetrics())

	// With temporal
	cv.Cvss3xTemporal = &Cvss3xTemporal{
		ExploitCodeMaturity: vector.ExploitCodeMaturityHigh,
	}
	assert.True(t, cv.HasTemporalMetrics())

	// Temporal struct but no metrics set
	cv2 := NewCvss3x()
	cv2.Cvss3xTemporal = &Cvss3xTemporal{}
	assert.False(t, cv2.HasTemporalMetrics())
}

func TestCvss3x_HasEnvironmentalMetrics(t *testing.T) {
	// No environmental
	cv := NewCvss3x()
	assert.False(t, cv.HasEnvironmentalMetrics())

	// With environmental
	cv.Cvss3xEnvironmental = &Cvss3xEnvironmental{
		ConfidentialityRequirement: vector.ConfidentialityRequirementHigh,
	}
	assert.True(t, cv.HasEnvironmentalMetrics())

	// Environmental struct but no metrics set
	cv2 := NewCvss3x()
	cv2.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
	assert.False(t, cv2.HasEnvironmentalMetrics())
}

func TestCvss3x_Equal(t *testing.T) {
	cv1 := NewCvss3x()
	cv1.MajorVersion = 3
	cv1.MinorVersion = 1
	cv1.Cvss3xBase = &Cvss3xBase{
		AttackVector:       vector.AttackVectorNetwork,
		AttackComplexity:   vector.AttackComplexityLow,
		PrivilegesRequired: vector.PrivilegesRequiredNone,
		UserInteraction:    vector.UserInteractionNone,
		Scope:              vector.ScopeUnchanged,
		Confidentiality:    vector.ConfidentialityHigh,
		Integrity:          vector.IntegrityHigh,
		Availability:       vector.AvailabilityHigh,
	}

	// Same
	cv2 := cv1.Clone()
	assert.True(t, cv1.Equal(cv2))

	// Different
	cv2.Cvss3xBase.AttackVector = vector.AttackVectorLocal
	assert.False(t, cv1.Equal(cv2))

	// Nil
	assert.False(t, cv1.Equal(nil))
	assert.False(t, (*Cvss3x)(nil).Equal(cv1))
}

func TestCvss3x_Clone(t *testing.T) {
	cv := NewCvss3x()
	cv.MajorVersion = 3
	cv.MinorVersion = 1
	cv.Cvss3xBase = &Cvss3xBase{
		AttackVector:     vector.AttackVectorNetwork,
		AttackComplexity: vector.AttackComplexityLow,
	}

	cloned := cv.Clone()
	assert.True(t, cv.Equal(cloned))

	// Verify deep copy — modifying clone should not affect original
	cloned.Cvss3xBase.AttackVector = vector.AttackVectorLocal
	assert.NotEqual(t, cv.Cvss3xBase.AttackVector, cloned.Cvss3xBase.AttackVector)
}

func TestCvss3x_BaseOnly(t *testing.T) {
	cv := NewCvss3x()
	cv.MajorVersion = 3
	cv.MinorVersion = 1
	cv.Cvss3xBase = &Cvss3xBase{
		AttackVector: vector.AttackVectorNetwork,
	}
	cv.Cvss3xTemporal = &Cvss3xTemporal{
		ExploitCodeMaturity: vector.ExploitCodeMaturityHigh,
	}
	cv.Cvss3xEnvironmental = &Cvss3xEnvironmental{
		ConfidentialityRequirement: vector.ConfidentialityRequirementHigh,
	}

	baseOnly := cv.BaseOnly()
	assert.NotNil(t, baseOnly.Cvss3xBase)
	assert.Nil(t, baseOnly.Cvss3xTemporal)
	assert.Nil(t, baseOnly.Cvss3xEnvironmental)
}

func TestCvss3xBase_Equal(t *testing.T) {
	b1 := &Cvss3xBase{
		AttackVector:     vector.AttackVectorNetwork,
		AttackComplexity: vector.AttackComplexityLow,
	}
	b2 := &Cvss3xBase{
		AttackVector:     vector.AttackVectorNetwork,
		AttackComplexity: vector.AttackComplexityLow,
	}
	assert.True(t, b1.Equal(b2))

	b2.AttackVector = vector.AttackVectorLocal
	assert.False(t, b1.Equal(b2))

	// Nil
	assert.False(t, b1.Equal(nil))
	assert.True(t, (*Cvss3xBase)(nil).Equal(nil))
}

func TestCvss3xTemporal_Equal(t *testing.T) {
	t1 := &Cvss3xTemporal{
		ExploitCodeMaturity: vector.ExploitCodeMaturityHigh,
	}
	t2 := &Cvss3xTemporal{
		ExploitCodeMaturity: vector.ExploitCodeMaturityHigh,
	}
	assert.True(t, t1.Equal(t2))

	t2.ExploitCodeMaturity = vector.ExploitCodeMaturityFunctional
	assert.False(t, t1.Equal(t2))
}

func TestCvss3xEnvironmental_Equal(t *testing.T) {
	e1 := &Cvss3xEnvironmental{
		ConfidentialityRequirement: vector.ConfidentialityRequirementHigh,
	}
	e2 := &Cvss3xEnvironmental{
		ConfidentialityRequirement: vector.ConfidentialityRequirementHigh,
	}
	assert.True(t, e1.Equal(e2))

	e2.ConfidentialityRequirement = vector.ConfidentialityRequirementLow
	assert.False(t, e1.Equal(e2))
}

// ==================== severity.go tests ====================

func TestGetSeverity(t *testing.T) {
	assert.Equal(t, SeverityNone, GetSeverity(0.0))
	assert.Equal(t, SeverityLow, GetSeverity(0.1))
	assert.Equal(t, SeverityLow, GetSeverity(3.9))
	assert.Equal(t, SeverityMedium, GetSeverity(4.0))
	assert.Equal(t, SeverityMedium, GetSeverity(6.9))
	assert.Equal(t, SeverityHigh, GetSeverity(7.0))
	assert.Equal(t, SeverityHigh, GetSeverity(8.9))
	assert.Equal(t, SeverityCritical, GetSeverity(9.0))
	assert.Equal(t, SeverityCritical, GetSeverity(10.0))
}

func TestParseSeverity(t *testing.T) {
	// Valid
	s, err := ParseSeverity("None")
	assert.NoError(t, err)
	assert.Equal(t, SeverityNone, s)

	s, err = ParseSeverity("Low")
	assert.NoError(t, err)
	assert.Equal(t, SeverityLow, s)

	s, err = ParseSeverity("Medium")
	assert.NoError(t, err)
	assert.Equal(t, SeverityMedium, s)

	s, err = ParseSeverity("High")
	assert.NoError(t, err)
	assert.Equal(t, SeverityHigh, s)

	s, err = ParseSeverity("Critical")
	assert.NoError(t, err)
	assert.Equal(t, SeverityCritical, s)

	// Case insensitive
	s, err = ParseSeverity("critical")
	assert.NoError(t, err)
	assert.Equal(t, SeverityCritical, s)

	// Invalid
	_, err = ParseSeverity("Unknown")
	assert.Error(t, err)
}

func TestSeverity_String(t *testing.T) {
	assert.Equal(t, "None", SeverityNone.String())
	assert.Equal(t, "Low", SeverityLow.String())
	assert.Equal(t, "Medium", SeverityMedium.String())
	assert.Equal(t, "High", SeverityHigh.String())
	assert.Equal(t, "Critical", SeverityCritical.String())
}

// ==================== scores.go tests ====================

func TestCalculator_GetBaseScore(t *testing.T) {
	cv := NewCvss3x()
	cv.MajorVersion = 3
	cv.MinorVersion = 1
	cv.Cvss3xBase = &Cvss3xBase{
		AttackVector:       vector.AttackVectorNetwork,
		AttackComplexity:   vector.AttackComplexityLow,
		PrivilegesRequired: vector.PrivilegesRequiredNone,
		UserInteraction:    vector.UserInteractionNone,
		Scope:              vector.ScopeUnchanged,
		Confidentiality:    vector.ConfidentialityHigh,
		Integrity:          vector.IntegrityHigh,
		Availability:       vector.AvailabilityHigh,
	}

	calc := NewCalculator(cv)
	score, err := calc.GetBaseScore()
	assert.NoError(t, err)
	assert.Equal(t, 9.8, score)
}

func TestCalculator_GetImpactSubScore(t *testing.T) {
	cv := NewCvss3x()
	cv.MajorVersion = 3
	cv.MinorVersion = 1
	cv.Cvss3xBase = &Cvss3xBase{
		AttackVector:       vector.AttackVectorNetwork,
		AttackComplexity:   vector.AttackComplexityLow,
		PrivilegesRequired: vector.PrivilegesRequiredNone,
		UserInteraction:    vector.UserInteractionNone,
		Scope:              vector.ScopeUnchanged,
		Confidentiality:    vector.ConfidentialityHigh,
		Integrity:          vector.IntegrityHigh,
		Availability:       vector.AvailabilityHigh,
	}

	calc := NewCalculator(cv)
	score, err := calc.GetImpactSubScore()
	assert.NoError(t, err)
	assert.Greater(t, score, 0.0)
}

func TestCalculator_GetExploitabilitySubScore(t *testing.T) {
	cv := NewCvss3x()
	cv.MajorVersion = 3
	cv.MinorVersion = 1
	cv.Cvss3xBase = &Cvss3xBase{
		AttackVector:       vector.AttackVectorNetwork,
		AttackComplexity:   vector.AttackComplexityLow,
		PrivilegesRequired: vector.PrivilegesRequiredNone,
		UserInteraction:    vector.UserInteractionNone,
		Scope:              vector.ScopeUnchanged,
		Confidentiality:    vector.ConfidentialityHigh,
		Integrity:          vector.IntegrityHigh,
		Availability:       vector.AvailabilityHigh,
	}

	calc := NewCalculator(cv)
	score, err := calc.GetExploitabilitySubScore()
	assert.NoError(t, err)
	assert.Greater(t, score, 0.0)
}

func TestCalculator_GetAllScores(t *testing.T) {
	cv := NewCvss3x()
	cv.MajorVersion = 3
	cv.MinorVersion = 1
	cv.Cvss3xBase = &Cvss3xBase{
		AttackVector:       vector.AttackVectorNetwork,
		AttackComplexity:   vector.AttackComplexityLow,
		PrivilegesRequired: vector.PrivilegesRequiredNone,
		UserInteraction:    vector.UserInteractionNone,
		Scope:              vector.ScopeUnchanged,
		Confidentiality:    vector.ConfidentialityHigh,
		Integrity:          vector.IntegrityHigh,
		Availability:       vector.AvailabilityHigh,
	}

	calc := NewCalculator(cv)
	scores, err := calc.GetAllScores()
	assert.NoError(t, err)
	assert.Equal(t, 9.8, scores.BaseScore)
	assert.Equal(t, SeverityCritical, scores.BaseSeverity)
	assert.Greater(t, scores.ImpactSubScore, 0.0)
	assert.Greater(t, scores.ExploitabilitySubScore, 0.0)
	assert.False(t, scores.HasTemporal)
	assert.False(t, scores.HasEnvironmental)
}

func TestCalculator_GetAllScores_WithEnvironmental(t *testing.T) {
	cv := NewCvss3x()
	cv.MajorVersion = 3
	cv.MinorVersion = 1
	cv.Cvss3xBase = &Cvss3xBase{
		AttackVector:       vector.AttackVectorNetwork,
		AttackComplexity:   vector.AttackComplexityLow,
		PrivilegesRequired: vector.PrivilegesRequiredNone,
		UserInteraction:    vector.UserInteractionNone,
		Scope:              vector.ScopeChanged,
		Confidentiality:    vector.ConfidentialityHigh,
		Integrity:          vector.IntegrityHigh,
		Availability:       vector.AvailabilityHigh,
	}
	cv.Cvss3xEnvironmental = &Cvss3xEnvironmental{
		ConfidentialityRequirement: vector.ConfidentialityRequirementHigh,
		IntegrityRequirement:       vector.IntegrityRequirementHigh,
		AvailabilityRequirement:    vector.AvailabilityRequirementHigh,
	}

	calc := NewCalculator(cv)
	scores, err := calc.GetAllScores()
	assert.NoError(t, err)
	assert.True(t, scores.HasEnvironmental)
	assert.Greater(t, scores.EnvironmentalScore, 0.0)
	assert.Greater(t, scores.ModifiedImpactSubScore, 0.0)
	assert.Greater(t, scores.ModifiedExploitabilitySubScore, 0.0)
}

func TestRoundUp_Public(t *testing.T) {
	assert.Equal(t, 3.2, RoundUp(3.11))
	assert.Equal(t, 4.0, RoundUp(3.99))
	assert.Equal(t, 10.0, RoundUp(9.91))
	assert.Equal(t, 0.0, RoundUp(0.0))
}

// ==================== distance_env.go tests ====================

func TestDistanceCalculator_EuclideanDistanceWithEnv(t *testing.T) {
	v1 := createEnvTestVector("Network", "Low", "None", "None", "Unchanged", "High", "High", "High",
		"High", "High", "High",
		"Network", "Low", "None", "None", "Unchanged", "High", "High", "High")
	v2 := createEnvTestVector("Network", "Low", "None", "None", "Unchanged", "High", "High", "High",
		"High", "High", "High",
		"Network", "Low", "None", "None", "Unchanged", "High", "High", "High")

	dc := NewDistanceCalculator(v1, v2)
	dist := dc.EuclideanDistanceWithEnv()
	assert.Equal(t, 0.0, dist)
}

func TestDistanceCalculator_ManhattanDistanceWithEnv(t *testing.T) {
	v1 := createEnvTestVector("Network", "Low", "None", "None", "Unchanged", "High", "High", "High",
		"High", "High", "High",
		"Network", "Low", "None", "None", "Unchanged", "High", "High", "High")
	v2 := createEnvTestVector("Network", "Low", "None", "None", "Unchanged", "High", "High", "High",
		"High", "High", "High",
		"Network", "Low", "None", "None", "Unchanged", "High", "High", "High")

	dc := NewDistanceCalculator(v1, v2)
	dist := dc.ManhattanDistanceWithEnv()
	assert.Equal(t, 0.0, dist)
}

func TestDistanceCalculator_HammingDistanceWithEnv(t *testing.T) {
	v1 := createEnvTestVector("Network", "Low", "None", "None", "Unchanged", "High", "High", "High",
		"High", "High", "High",
		"Network", "Low", "None", "None", "Unchanged", "High", "High", "High")
	v2 := createEnvTestVector("Network", "Low", "None", "None", "Unchanged", "High", "High", "High",
		"High", "High", "High",
		"Network", "Low", "None", "None", "Unchanged", "High", "High", "High")

	dc := NewDistanceCalculator(v1, v2)
	dist := dc.HammingDistanceWithEnv()
	assert.Equal(t, 0, dist)
}

func TestDistanceCalculator_HammingDistanceWithEnv_Different(t *testing.T) {
	v1 := createEnvTestVector("Network", "Low", "None", "None", "Unchanged", "High", "High", "High",
		"High", "High", "High",
		"Network", "Low", "None", "None", "Unchanged", "High", "High", "High")
	v2 := createEnvTestVector("Local", "High", "None", "None", "Unchanged", "Low", "Low", "Low",
		"Low", "Low", "Low",
		"Local", "High", "None", "None", "Unchanged", "Low", "Low", "Low")

	dc := NewDistanceCalculator(v1, v2)
	dist := dc.HammingDistanceWithEnv()
	assert.Greater(t, dist, 0)
}

// Helper to create a Cvss3x with environmental metrics
func createEnvTestVector(av, ac, pr, ui, s, c, i, a string,
	cr, ir, ar string,
	mav, mac, mpr, mui, ms, mc, mi, ma string) *Cvss3x {

	cv := createTestVector(3, 1, av, ac, pr, ui, s, c, i, a)
	cv.Cvss3xEnvironmental = &Cvss3xEnvironmental{
		ConfidentialityRequirement: getRequirement(cr, "CR"),
		IntegrityRequirement:       getRequirement(ir, "IR"),
		AvailabilityRequirement:    getRequirement(ar, "AR"),
		ModifiedAttackVector:       getModifiedVector(mav, "MAV"),
		ModifiedAttackComplexity:   getModifiedVector(mac, "MAC"),
		ModifiedPrivilegesRequired: getModifiedVector(mpr, "MPR"),
		ModifiedUserInteraction:    getModifiedVector(mui, "MUI"),
		ModifiedScope:              getModifiedVector(ms, "MS"),
		ModifiedConfidentiality:    getModifiedVector(mc, "MC"),
		ModifiedIntegrity:          getModifiedVector(mi, "MI"),
		ModifiedAvailability:       getModifiedVector(ma, "MA"),
	}
	return cv
}

func getRequirement(val, shortName string) vector.Vector {
	switch val {
	case "High":
		if shortName == "CR" {
			return vector.ConfidentialityRequirementHigh
		} else if shortName == "IR" {
			return vector.IntegrityRequirementHigh
		}
		return vector.AvailabilityRequirementHigh
	case "Medium":
		if shortName == "CR" {
			return vector.ConfidentialityRequirementMedium
		} else if shortName == "IR" {
			return vector.IntegrityRequirementMedium
		}
		return vector.AvailabilityRequirementMedium
	case "Low":
		if shortName == "CR" {
			return vector.ConfidentialityRequirementLow
		} else if shortName == "IR" {
			return vector.IntegrityRequirementLow
		}
		return vector.AvailabilityRequirementLow
	default:
		return nil
	}
}

func getModifiedVector(val, shortName string) vector.Vector {
	switch shortName {
	case "MAV":
		v, _ := vector.GetModifiedAttackVector(rune(val[0]))
		return v
	case "MAC":
		v, _ := vector.GetModifiedAttackComplexity(rune(val[0]))
		return v
	case "MPR":
		v, _ := vector.GetModifiedPrivilegesRequired(rune(val[0]))
		return v
	case "MUI":
		v, _ := vector.GetModifiedUserInteraction(rune(val[0]))
		return v
	case "MS":
		v, _ := vector.GetModifiedScope(rune(val[0]))
		return v
	case "MC":
		v, _ := vector.GetModifiedConfidentiality(rune(val[0]))
		return v
	case "MI":
		v, _ := vector.GetModifiedIntegrity(rune(val[0]))
		return v
	case "MA":
		v, _ := vector.GetModifiedAvailability(rune(val[0]))
		return v
	default:
		return nil
	}
}
