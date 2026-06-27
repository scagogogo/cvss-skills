package mock

import (
	"testing"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/stretchr/testify/assert"
)

func TestCriticalCvss31(t *testing.T) {
	cv := CriticalCvss31()
	assert.NotNil(t, cv)
	assert.Equal(t, 3, cv.MajorVersion)
	assert.Equal(t, 1, cv.MinorVersion)
	assert.NotNil(t, cv.Cvss3xBase)
}

func TestHighCvss31(t *testing.T) {
	cv := HighCvss31()
	assert.NotNil(t, cv)
	assert.Equal(t, 3, cv.MajorVersion)
	assert.Equal(t, 1, cv.MinorVersion)
}

func TestMediumCvss31(t *testing.T) {
	cv := MediumCvss31()
	assert.NotNil(t, cv)
	assert.Equal(t, 3, cv.MajorVersion)
	assert.Equal(t, 1, cv.MinorVersion)
}

func TestLowCvss31(t *testing.T) {
	cv := LowCvss31()
	assert.NotNil(t, cv)
	assert.Equal(t, 3, cv.MajorVersion)
	assert.Equal(t, 1, cv.MinorVersion)
}

func TestNoneCvss31(t *testing.T) {
	cv := NoneCvss31()
	assert.NotNil(t, cv)
	assert.Equal(t, 3, cv.MajorVersion)
	assert.Equal(t, 1, cv.MinorVersion)
}

func TestRandomCvss3x(t *testing.T) {
	cv := RandomCvss3x(1)
	assert.NotNil(t, cv)
	assert.Equal(t, 3, cv.MajorVersion)
	assert.Equal(t, 1, cv.MinorVersion)
	assert.NotNil(t, cv.Cvss3xBase)
}

func TestRandomCvss3xWithTemporal(t *testing.T) {
	cv := RandomCvss3xWithTemporal(1)
	assert.NotNil(t, cv)
	assert.NotNil(t, cv.Cvss3xTemporal)
}

func TestRandomCvss3xFull(t *testing.T) {
	cv := RandomCvss3xFull(1)
	assert.NotNil(t, cv)
	assert.NotNil(t, cv.Cvss3xTemporal)
	assert.NotNil(t, cv.Cvss3xEnvironmental)
}

func TestRandomCvss3xVectorString(t *testing.T) {
	s := RandomCvss3xVectorString(1)
	assert.NotEmpty(t, s)
	assert.Contains(t, s, "CVSS:3.1")
}

func TestRandomCvss3xWithScore(t *testing.T) {
	cv, score, err := RandomCvss3xWithScore(1)
	assert.NoError(t, err)
	assert.NotNil(t, cv)
	assert.GreaterOrEqual(t, score, 0.0)
	assert.LessOrEqual(t, score, 10.0)
}

func TestPresetSeverities(t *testing.T) {
	// Verify preset vectors produce expected severity ranges via Calculator
	testCases := []struct {
		name     string
		preset   func() *cvss.Cvss3x
		minScore float64
		maxScore float64
	}{
		{"Critical", CriticalCvss31, 9.0, 10.0},
		{"High", HighCvss31, 7.0, 10.0},
		{"Medium", MediumCvss31, 4.0, 7.0},
		{"Low", LowCvss31, 0.1, 4.0},
		{"None", NoneCvss31, 0.0, 0.0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cv := tc.preset()
			calc := cvss.NewCalculator(cv)
			score, err := calc.Calculate()
			assert.NoError(t, err)
			assert.GreaterOrEqual(t, score, tc.minScore, "%s preset score should be >= %f", tc.name, tc.minScore)
			assert.LessOrEqual(t, score, tc.maxScore, "%s preset score should be <= %f", tc.name, tc.maxScore)
		})
	}
}
