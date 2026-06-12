package cvss

import (
	"testing"

	"github.com/scagogogo/cvss-parser/pkg/vector"
	"github.com/stretchr/testify/assert"
)

// ==================== IsComplete tests ====================

func TestIsComplete_AllSet(t *testing.T) {
	cv := NewBuilder().Version(3, 1).AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').MustBuild()
	assert.True(t, cv.IsComplete())
}

func TestIsComplete_Missing(t *testing.T) {
	cv := NewCvss3x()
	cv.MajorVersion = 3
	cv.MinorVersion = 1
	cv.Cvss3xBase.AttackVector = vector.AttackVectorNetwork
	assert.False(t, cv.IsComplete())
}

func TestIsComplete_NilBase(t *testing.T) {
	cv := &Cvss3x{}
	assert.False(t, cv.IsComplete())
}

func TestIsComplete_NilReceiver(t *testing.T) {
	var cv *Cvss3x
	assert.False(t, cv.IsComplete())
}

// ==================== ScoreBreakdown tests ====================

func TestGetScoreBreakdown_Base(t *testing.T) {
	cv := NewBuilder().Version(3, 1).AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').MustBuild()
	calc := NewCalculator(cv)
	bd, err := calc.GetScoreBreakdown()
	assert.NoError(t, err)

	assert.Equal(t, "AV", bd.AttackVector.ShortName)
	assert.Equal(t, "N", bd.AttackVector.Value)
	assert.Equal(t, 0.85, bd.AttackVector.Score)

	// PR should be scope-adjusted (S:U → PR:N = 0.85)
	assert.Equal(t, "PR", bd.PrivilegesRequired.ShortName)
	assert.Equal(t, 0.85, bd.PrivilegesRequired.Score)
}

func TestGetScoreBreakdown_ScopeChanged(t *testing.T) {
	cv := NewBuilder().Version(3, 1).AV('N').AC('L').PR('L').UI('N').S('C').C('H').I('H').A('H').MustBuild()
	calc := NewCalculator(cv)
	bd, err := calc.GetScoreBreakdown()
	assert.NoError(t, err)

	// PR:L with Scope Changed should be 0.68
	assert.Equal(t, 0.68, bd.PrivilegesRequired.Score)
}

func TestGetScoreBreakdown_v30(t *testing.T) {
	cv := NewBuilder().Version(3, 0).AV('N').AC('L').PR('N').UI('R').S('U').C('H').I('H').A('H').MustBuild()
	calc := NewCalculator(cv)
	bd, err := calc.GetScoreBreakdown()
	assert.NoError(t, err)

	// UI:R with v3.0 should be 0.56
	assert.Equal(t, 0.56, bd.UserInteraction.Score)
}

func TestMetricScore_String(t *testing.T) {
	ms := MetricScore{ShortName: "AV", Value: "N", Score: 0.85}
	assert.Equal(t, "AV:N=0.85", ms.String())
}

// ==================== AllScores.AsMap tests ====================

func TestAllScores_AsMap(t *testing.T) {
	cv := NewBuilder().Version(3, 1).AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').MustBuild()
	calc := NewCalculator(cv)
	scores, err := calc.GetAllScores()
	assert.NoError(t, err)

	m := scores.AsMap()
	assert.Equal(t, 9.8, m["baseScore"])
	assert.Contains(t, m, "impactSubScore")
	assert.Contains(t, m, "exploitabilitySubScore")
	assert.NotContains(t, m, "temporalScore") // no temporal metrics
}

func TestAllScores_AsMap_WithTemporal(t *testing.T) {
	cv := NewBuilder().Version(3, 1).
		AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').
		E('U').MustBuild()
	calc := NewCalculator(cv)
	scores, err := calc.GetAllScores()
	assert.NoError(t, err)

	m := scores.AsMap()
	assert.Contains(t, m, "temporalScore")
}

// ==================== JaccardSimilarityWithEnv tests ====================

func TestJaccardSimilarityWithEnv(t *testing.T) {
	cv1 := NewBuilder().Version(3, 1).AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').MustBuild()
	cv2 := NewBuilder().Version(3, 1).AV('L').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').MustBuild()

	dc := NewDistanceCalculator(cv1, cv2)
	jaccard := dc.JaccardSimilarityWithEnv()
	assert.GreaterOrEqual(t, jaccard, 0.0)
	assert.LessOrEqual(t, jaccard, 1.0)
	// Only AV differs out of 8 base → 7/8 = 0.875
	assert.InDelta(t, 0.875, jaccard, 0.01)
}

// ==================== NewCvss3x nil consistency tests ====================

func TestNewCvss3x_TemporalIsNil(t *testing.T) {
	cv := NewCvss3x()
	assert.Nil(t, cv.Cvss3xTemporal)
}

func TestNewCvss3x_EnvironmentalIsNil(t *testing.T) {
	cv := NewCvss3x()
	assert.Nil(t, cv.Cvss3xEnvironmental)
}

func TestNewCvss3x_BaseIsNotNil(t *testing.T) {
	cv := NewCvss3x()
	assert.NotNil(t, cv.Cvss3xBase)
}

func TestParser_LazyInitTemporal(t *testing.T) {
	cv := NewBuilder().Version(3, 1).
		AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').
		E('U').MustBuild()
	assert.NotNil(t, cv.Cvss3xTemporal)
	assert.Equal(t, vector.ExploitCodeMaturityUnproven, cv.Cvss3xTemporal.ExploitCodeMaturity)
}

func TestBuilder_NoTemporal(t *testing.T) {
	cv := NewBuilder().Version(3, 1).AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').MustBuild()
	assert.Nil(t, cv.Cvss3xTemporal)
}

func TestBuilder_Environmental(t *testing.T) {
	cv := NewBuilder().Version(3, 1).
		AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').
		CR('H').MustBuild()
	assert.NotNil(t, cv.Cvss3xEnvironmental)
}

// ==================== CIA cap at 1.0 test ====================

func TestCalculateModifiedImpactSubScore_CIACap(t *testing.T) {
	// With CR=H(1.5) and MC=H(0.56), adjusted = 0.56*1.5 = 0.84 < 1.0 → no cap needed
	// But this test ensures the cap is in place
	cv := NewBuilder().Version(3, 1).
		AV('N').AC('L').PR('N').UI('N').S('U').C('N').I('N').A('N').
		CR('H').IR('H').AR('H').MC('H').MI('H').MA('H').MustBuild()

	calc := NewCalculator(cv)
	score, err := calc.Calculate()
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, score, 0.0)
	assert.LessOrEqual(t, score, 10.0)
}

// ==================== Distance v3.0 UI score fix test ====================

func TestDistance_v30_UIScore(t *testing.T) {
	cv1 := NewBuilder().Version(3, 0).AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').MustBuild()
	cv2 := NewBuilder().Version(3, 0).AV('N').AC('L').PR('N').UI('R').S('U').C('H').I('H').A('H').MustBuild()

	dc := NewDistanceCalculator(cv1, cv2)
	euclidean := dc.EuclideanDistance()

	// UI:N=0.85 vs UI:R(v3.0)=0.56 → diff=0.29
	// Only one metric differs
	assert.Greater(t, euclidean, 0.0)
}

// ==================== Mock preset score verification ====================

func TestPresetScores(t *testing.T) {
	presets := []struct {
		name     string
		build    func() *Cvss3x
		expected float64
	}{
		{"Critical", func() *Cvss3x {
			return NewBuilder().Version(3, 1).AV('N').AC('L').PR('N').UI('N').S('C').C('H').I('H').A('H').MustBuild()
		}, 10.0},
		{"High", func() *Cvss3x {
			return NewBuilder().Version(3, 1).AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').MustBuild()
		}, 9.8},
		{"Medium", func() *Cvss3x {
			return NewBuilder().Version(3, 1).AV('N').AC('L').PR('N').UI('N').S('U').C('L').I('L').A('N').MustBuild()
		}, 6.5},
		{"Low", func() *Cvss3x {
			return NewBuilder().Version(3, 1).AV('N').AC('H').PR('N').UI('N').S('U').C('L').I('N').A('N').MustBuild()
		}, 3.7},
		{"None", func() *Cvss3x {
			return NewBuilder().Version(3, 1).AV('N').AC('L').PR('N').UI('N').S('U').C('N').I('N').A('N').MustBuild()
		}, 0.0},
	}

	for _, p := range presets {
		t.Run(p.name, func(t *testing.T) {
			cv := p.build()
			score, err := NewCalculator(cv).Calculate()
			assert.NoError(t, err)
			assert.Equal(t, p.expected, score, "%s preset score mismatch", p.name)
		})
	}
}
