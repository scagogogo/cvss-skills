package cvss

import (
	"testing"

	"github.com/scagogogo/cvss-skills/pkg/vector"
	"github.com/stretchr/testify/assert"
)

// TestNewCalculator 测试创建新计算器
func TestNewCalculator(t *testing.T) {
	cvss := NewCvss3x()
	calc := NewCalculator(cvss)
	assert.NotNil(t, calc)
	assert.Equal(t, cvss, calc.cvss)
}

// TestRoundUp 测试向上取整函数
func TestRoundUp(t *testing.T) {
	testCases := []struct {
		input    float64
		expected float64
	}{
		{0.0, 0.0},
		{1.0, 1.0},
		{5.3, 5.3},
		{5.35, 5.4},
		{5.36, 5.4},
		{9.99, 10.0},
	}

	for _, tc := range testCases {
		result := roundUp(tc.input)
		assert.Equal(t, tc.expected, result, "RoundUp(%v) = %v, want %v", tc.input, result, tc.expected)
	}
}

// TestCalculateBaseScore 测试基础评分计算
func TestCalculateBaseScore(t *testing.T) {
	// Test cases - directly create CVSS objects for testing
	testCases := []struct {
		name     string
		cvss     *Cvss3x
		expected float64
	}{
		{
			name: "Critical - Network AV, Low AC, No PR, No UI, Changed Scope, High CIA",
			cvss: &Cvss3x{
				MajorVersion: 3,
				MinorVersion: 1,
				Cvss3xBase: &Cvss3xBase{
					AttackVector:       vector.AttackVectorNetwork,
					AttackComplexity:   vector.AttackComplexityLow,
					PrivilegesRequired: vector.PrivilegesRequiredNone,
					UserInteraction:    vector.UserInteractionNone,
					Scope:              vector.ScopeChanged,
					Confidentiality:    vector.ConfidentialityHigh,
					Integrity:          vector.IntegrityHigh,
					Availability:       vector.AvailabilityHigh,
				},
			},
			expected: 10.0,
		},
		{
			name: "High - Local AV, Low AC, Low PR, No UI, Unchanged Scope, High CIA",
			cvss: &Cvss3x{
				MajorVersion: 3,
				MinorVersion: 1,
				Cvss3xBase: &Cvss3xBase{
					AttackVector:       vector.AttackVectorLocal,
					AttackComplexity:   vector.AttackComplexityLow,
					PrivilegesRequired: vector.PrivilegesRequiredLow,
					UserInteraction:    vector.UserInteractionNone,
					Scope:              vector.ScopeUnchanged,
					Confidentiality:    vector.ConfidentialityHigh,
					Integrity:          vector.IntegrityHigh,
					Availability:       vector.AvailabilityHigh,
				},
			},
			expected: 7.8,
		},
		{
			name: "Medium - Network AV, High AC, No PR, Required UI, Unchanged Scope, Low CIA",
			cvss: &Cvss3x{
				MajorVersion: 3,
				MinorVersion: 1,
				Cvss3xBase: &Cvss3xBase{
					AttackVector:       vector.AttackVectorNetwork,
					AttackComplexity:   vector.AttackComplexityHigh,
					PrivilegesRequired: vector.PrivilegesRequiredNone,
					UserInteraction:    vector.UserInteractionRequired,
					Scope:              vector.ScopeUnchanged,
					Confidentiality:    vector.ConfidentialityLow,
					Integrity:          vector.IntegrityLow,
					Availability:       vector.AvailabilityLow,
				},
			},
			expected: 5.0,
		},
		{
			name: "Low - Physical AV, High AC, High PR, Required UI, Unchanged Scope, Low C&I, None A",
			cvss: &Cvss3x{
				MajorVersion: 3,
				MinorVersion: 1,
				Cvss3xBase: &Cvss3xBase{
					AttackVector:       vector.AttackVectorPhysical,
					AttackComplexity:   vector.AttackComplexityHigh,
					PrivilegesRequired: vector.PrivilegesRequiredHigh,
					UserInteraction:    vector.UserInteractionRequired,
					Scope:              vector.ScopeUnchanged,
					Confidentiality:    vector.ConfidentialityLow,
					Integrity:          vector.IntegrityLow,
					Availability:       vector.AvailabilityNone,
				},
			},
			expected: 2.7,
		},
		{
			name: "None - Physical AV, High AC, High PR, Required UI, Unchanged Scope, None CIA",
			cvss: &Cvss3x{
				MajorVersion: 3,
				MinorVersion: 1,
				Cvss3xBase: &Cvss3xBase{
					AttackVector:       vector.AttackVectorPhysical,
					AttackComplexity:   vector.AttackComplexityHigh,
					PrivilegesRequired: vector.PrivilegesRequiredHigh,
					UserInteraction:    vector.UserInteractionRequired,
					Scope:              vector.ScopeUnchanged,
					Confidentiality:    vector.ConfidentialityNone,
					Integrity:          vector.IntegrityNone,
					Availability:       vector.AvailabilityNone,
				},
			},
			expected: 0.0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			calculator := NewCalculator(tc.cvss)
			score := calculator.calculateBaseScore()
			assert.InDelta(t, tc.expected, score, 0.1, "Base score calculation error")
		})
	}
}

// TestCalculateImpactSubScore 测试影响子评分计算
func TestCalculateImpactSubScore(t *testing.T) {
	testCases := []struct {
		name     string
		cvss     *Cvss3x
		expected float64
	}{
		{
			name: "High CIA, Unchanged Scope",
			cvss: &Cvss3x{
				Cvss3xBase: &Cvss3xBase{
					Scope:           vector.ScopeUnchanged,
					Confidentiality: vector.ConfidentialityHigh,
					Integrity:       vector.IntegrityHigh,
					Availability:    vector.AvailabilityHigh,
				},
			},
			expected: 6.0, // approximate
		},
		{
			name: "Low CIA, Unchanged Scope",
			cvss: &Cvss3x{
				Cvss3xBase: &Cvss3xBase{
					Scope:           vector.ScopeUnchanged,
					Confidentiality: vector.ConfidentialityLow,
					Integrity:       vector.IntegrityLow,
					Availability:    vector.AvailabilityLow,
				},
			},
			expected: 3.4, // approximate
		},
		{
			name: "High CIA, Changed Scope",
			cvss: &Cvss3x{
				Cvss3xBase: &Cvss3xBase{
					Scope:           vector.ScopeChanged,
					Confidentiality: vector.ConfidentialityHigh,
					Integrity:       vector.IntegrityHigh,
					Availability:    vector.AvailabilityHigh,
				},
			},
			expected: 6.0, // approximate
		},
		{
			name: "None CIA, Any Scope",
			cvss: &Cvss3x{
				Cvss3xBase: &Cvss3xBase{
					Scope:           vector.ScopeUnchanged,
					Confidentiality: vector.ConfidentialityNone,
					Integrity:       vector.IntegrityNone,
					Availability:    vector.AvailabilityNone,
				},
			},
			expected: 0.0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			calculator := NewCalculator(tc.cvss)
			score := calculator.calculateImpactSubScore()
			assert.InDelta(t, tc.expected, score, 0.5, "Impact subscore calculation error")
		})
	}
}

// TestCalculateExploitabilitySubScore 测试可利用性子评分计算
func TestCalculateExploitabilitySubScore(t *testing.T) {
	testCases := []struct {
		name     string
		cvss     *Cvss3x
		expected float64
	}{
		{
			name: "Network AV, Low AC, No PR, No UI, Unchanged Scope",
			cvss: &Cvss3x{
				Cvss3xBase: &Cvss3xBase{
					AttackVector:       vector.AttackVectorNetwork,
					AttackComplexity:   vector.AttackComplexityLow,
					PrivilegesRequired: vector.PrivilegesRequiredNone,
					UserInteraction:    vector.UserInteractionNone,
					Scope:              vector.ScopeUnchanged,
				},
			},
			expected: 3.9, // 8.22 * 0.85 * 0.77 * 0.85 * 0.85
		},
		{
			name: "Network AV, Low AC, Low PR, No UI, Changed Scope",
			cvss: &Cvss3x{
				Cvss3xBase: &Cvss3xBase{
					AttackVector:       vector.AttackVectorNetwork,
					AttackComplexity:   vector.AttackComplexityLow,
					PrivilegesRequired: vector.PrivilegesRequiredLow,
					UserInteraction:    vector.UserInteractionNone,
					Scope:              vector.ScopeChanged,
				},
			},
			expected: 3.11, // Updated to match actual calculation value
		},
		{
			name: "Adjacent AV, High AC, High PR, Required UI, Unchanged Scope",
			cvss: &Cvss3x{
				Cvss3xBase: &Cvss3xBase{
					AttackVector:       vector.AttackVectorAdjacent,
					AttackComplexity:   vector.AttackComplexityHigh,
					PrivilegesRequired: vector.PrivilegesRequiredHigh,
					UserInteraction:    vector.UserInteractionRequired,
					Scope:              vector.ScopeUnchanged,
				},
			},
			expected: 0.4, // 8.22 * 0.62 * 0.44 * 0.27 * 0.62
		},
		{
			name: "Physical AV, High AC, High PR, Required UI, Changed Scope",
			cvss: &Cvss3x{
				Cvss3xBase: &Cvss3xBase{
					AttackVector:       vector.AttackVectorPhysical,
					AttackComplexity:   vector.AttackComplexityHigh,
					PrivilegesRequired: vector.PrivilegesRequiredHigh,
					UserInteraction:    vector.UserInteractionRequired,
					Scope:              vector.ScopeChanged,
				},
			},
			expected: 0.3, // 8.22 * 0.2 * 0.44 * 0.5 * 0.62
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			calculator := NewCalculator(tc.cvss)
			score := calculator.calculateExploitabilitySubScore()
			assert.InDelta(t, tc.expected, score, 0.1, "Exploitability subscore calculation error")
		})
	}
}

// TestGetAdjustedPrivilegesRequiredScore 测试特权要求评分调整
func TestGetAdjustedPrivilegesRequiredScore(t *testing.T) {
	testCases := []struct {
		name     string
		pr       vector.Vector
		scope    vector.Vector
		expected float64
	}{
		{"PR None, Scope Unchanged", vector.PrivilegesRequiredNone, vector.ScopeUnchanged, 0.85},
		{"PR Low, Scope Unchanged", vector.PrivilegesRequiredLow, vector.ScopeUnchanged, 0.62},
		{"PR High, Scope Unchanged", vector.PrivilegesRequiredHigh, vector.ScopeUnchanged, 0.27},
		{"PR None, Scope Changed", vector.PrivilegesRequiredNone, vector.ScopeChanged, 0.85},
		{"PR Low, Scope Changed", vector.PrivilegesRequiredLow, vector.ScopeChanged, 0.68},
		{"PR High, Scope Changed", vector.PrivilegesRequiredHigh, vector.ScopeChanged, 0.50},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cvss := &Cvss3x{
				Cvss3xBase: &Cvss3xBase{
					PrivilegesRequired: tc.pr,
					Scope:              tc.scope,
				},
			}
			calculator := NewCalculator(cvss)
			score := calculator.getAdjustedPrivilegesRequiredScore()
			assert.Equal(t, tc.expected, score, "Adjusted PR score calculation error")
		})
	}
}

// TestIsChangedScope 测试范围是否改变判断
func TestIsChangedScope(t *testing.T) {
	testCases := []struct {
		name     string
		scope    vector.Vector
		expected bool
	}{
		{"Scope Unchanged", vector.ScopeUnchanged, false},
		{"Scope Changed", vector.ScopeChanged, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cvss := &Cvss3x{
				Cvss3xBase: &Cvss3xBase{
					Scope: tc.scope,
				},
			}
			calculator := NewCalculator(cvss)
			result := calculator.isChangedScope()
			assert.Equal(t, tc.expected, result, "Changed scope detection error")
		})
	}
}

// TestCalculateTemporalScore 测试时间评分计算
func TestCalculateTemporalScore(t *testing.T) {
	testCases := []struct {
		name      string
		baseScore float64
		cvss      *Cvss3x
		expected  float64
	}{
		{
			name:      "All Not Defined",
			baseScore: 7.5,
			cvss: &Cvss3x{
				Cvss3xTemporal: &Cvss3xTemporal{
					ExploitCodeMaturity: vector.ExploitCodeMaturityNotDefined,
					RemediationLevel:    vector.RemediationLevelNotDefined,
					ReportConfidence:    vector.ReportConfidenceNotDefined,
				},
			},
			expected: 7.5,
		},
		{
			name:      "Functional, Official Fix, Confirmed",
			baseScore: 7.5,
			cvss: &Cvss3x{
				Cvss3xTemporal: &Cvss3xTemporal{
					ExploitCodeMaturity: vector.ExploitCodeMaturityFunctional,
					RemediationLevel:    vector.RemediationLevelOfficialFix,
					ReportConfidence:    vector.ReportConfidenceConfirmed,
				},
			},
			expected: 7.0, // 7.5 * 0.97 * 0.95 * 1.0 = 6.9825, rounded to 7.0
		},
		{
			name:      "Unproven, Workaround, Unknown",
			baseScore: 7.5,
			cvss: &Cvss3x{
				Cvss3xTemporal: &Cvss3xTemporal{
					ExploitCodeMaturity: vector.ExploitCodeMaturityUnproven,
					RemediationLevel:    vector.RemediationLevelWorkaround,
					ReportConfidence:    vector.ReportConfidenceUnknown,
				},
			},
			expected: 6.1, // Updated to match actual calculation value
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			calculator := NewCalculator(tc.cvss)
			score := calculator.calculateTemporalScore(tc.baseScore)
			assert.InDelta(t, tc.expected, score, 0.1, "Temporal score calculation error")
		})
	}
}

// TestHasTemporalMetrics 测试是否存在时间指标判断
func TestHasTemporalMetrics(t *testing.T) {
	testCases := []struct {
		name     string
		cvss     *Cvss3x
		expected bool
	}{
		{
			name:     "No Temporal Metrics",
			cvss:     &Cvss3x{},
			expected: false,
		},
		{
			name: "Partial Temporal Metrics",
			cvss: &Cvss3x{
				Cvss3xTemporal: &Cvss3xTemporal{
					ExploitCodeMaturity: vector.ExploitCodeMaturityFunctional,
				},
			},
			expected: true, // 只要有任一 Temporal 指标，就认为需要计算 Temporal 评分
		},
		{
			name: "Complete Temporal Metrics",
			cvss: &Cvss3x{
				Cvss3xTemporal: &Cvss3xTemporal{
					ExploitCodeMaturity: vector.ExploitCodeMaturityFunctional,
					RemediationLevel:    vector.RemediationLevelOfficialFix,
					ReportConfidence:    vector.ReportConfidenceConfirmed,
				},
			},
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			calculator := NewCalculator(tc.cvss)
			result := calculator.hasTemporalMetrics()
			assert.Equal(t, tc.expected, result, "Temporal metrics detection error")
		})
	}
}

// TestHasEnvironmentalMetrics 测试是否存在环境指标判断
func TestHasEnvironmentalMetrics(t *testing.T) {
	testCases := []struct {
		name     string
		cvss     *Cvss3x
		expected bool
	}{
		{
			name:     "No Environmental Metrics",
			cvss:     &Cvss3x{},
			expected: false,
		},
		{
			name: "With CIA Requirements",
			cvss: &Cvss3x{
				Cvss3xEnvironmental: &Cvss3xEnvironmental{
					ConfidentialityRequirement: vector.ConfidentialityRequirementHigh,
					IntegrityRequirement:       vector.IntegrityRequirementMedium,
					AvailabilityRequirement:    vector.AvailabilityRequirementLow,
				},
			},
			expected: true,
		},
		{
			name: "With Modified Metrics",
			cvss: &Cvss3x{
				Cvss3xEnvironmental: &Cvss3xEnvironmental{
					ModifiedAttackVector:     vector.ModifiedAttackVectorAdjacent,
					ModifiedAttackComplexity: vector.ModifiedAttackComplexityHigh,
				},
			},
			expected: true,
		},
		{
			name: "With One Modified Metric",
			cvss: &Cvss3x{
				Cvss3xEnvironmental: &Cvss3xEnvironmental{
					ModifiedConfidentiality: vector.ModifiedConfidentialityLow,
				},
			},
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			calculator := NewCalculator(tc.cvss)
			result := calculator.hasEnvironmentalMetrics()
			assert.Equal(t, tc.expected, result, "Environmental metrics detection error")
		})
	}
}

// TestGetSeverityRating 测试严重性等级获取
func TestGetSeverityRating(t *testing.T) {
	testCases := []struct {
		score    float64
		expected Severity
	}{
		{0.0, SeverityNone},
		{0.1, SeverityLow},
		{3.9, SeverityLow},
		{4.0, SeverityMedium},
		{6.9, SeverityMedium},
		{7.0, SeverityHigh},
		{8.9, SeverityHigh},
		{9.0, SeverityCritical},
		{10.0, SeverityCritical},
	}

	calc := NewCalculator(nil) // Score is parameter, CVSS not used
	for _, tc := range testCases {
		severity := calc.GetSeverityRating(tc.score)
		assert.Equal(t, tc.expected, severity, "Severity rating error for score %f", tc.score)
	}
}

// TestCalculate 集成测试计算函数
func TestCalculate(t *testing.T) {
	// 基础评分测试
	t.Run("Base Score Only", func(t *testing.T) {
		cvss := &Cvss3x{
			MajorVersion: 3,
			MinorVersion: 1,
			Cvss3xBase: &Cvss3xBase{
				AttackVector:       vector.AttackVectorNetwork,
				AttackComplexity:   vector.AttackComplexityHigh,
				PrivilegesRequired: vector.PrivilegesRequiredNone,
				UserInteraction:    vector.UserInteractionRequired,
				Scope:              vector.ScopeUnchanged,
				Confidentiality:    vector.ConfidentialityLow,
				Integrity:          vector.IntegrityLow,
				Availability:       vector.AvailabilityLow,
			},
		}
		calculator := NewCalculator(cvss)
		score, err := calculator.Calculate()
		assert.NoError(t, err)
		assert.InDelta(t, 5.0, score, 0.1)
	})

	// 时间评分测试
	t.Run("Temporal Score", func(t *testing.T) {
		cvss := &Cvss3x{
			MajorVersion: 3,
			MinorVersion: 1,
			Cvss3xBase: &Cvss3xBase{
				AttackVector:       vector.AttackVectorNetwork,
				AttackComplexity:   vector.AttackComplexityLow,
				PrivilegesRequired: vector.PrivilegesRequiredNone,
				UserInteraction:    vector.UserInteractionNone,
				Scope:              vector.ScopeUnchanged,
				Confidentiality:    vector.ConfidentialityHigh,
				Integrity:          vector.IntegrityHigh,
				Availability:       vector.AvailabilityHigh,
			},
			Cvss3xTemporal: &Cvss3xTemporal{
				ExploitCodeMaturity: vector.ExploitCodeMaturityFunctional,
				RemediationLevel:    vector.RemediationLevelOfficialFix,
				ReportConfidence:    vector.ReportConfidenceConfirmed,
			},
		}
		calculator := NewCalculator(cvss)
		score, err := calculator.Calculate()
		assert.NoError(t, err)
		assert.InDelta(t, 9.1, score, 0.5) // 9.8 * 0.97 * 0.95 * 1.0 = ~9.0, rounded up
	})

	// 环境评分测试 - 已经在其他测试文件中进行了充分测试
}

// TestGetRequirementFactors 测试安全需求因子获取
func TestGetRequirementFactors(t *testing.T) {
	testCases := []struct {
		name      string
		cReq      vector.Vector
		iReq      vector.Vector
		aReq      vector.Vector
		expCRFact float64
		expIRFact float64
		expARFact float64
	}{
		{
			name:      "All Not Defined",
			cReq:      vector.ConfidentialityRequirementNotDefined,
			iReq:      vector.IntegrityRequirementNotDefined,
			aReq:      vector.AvailabilityRequirementNotDefined,
			expCRFact: 1.0,
			expIRFact: 1.0,
			expARFact: 1.0,
		},
		{
			name:      "All Low",
			cReq:      vector.ConfidentialityRequirementLow,
			iReq:      vector.IntegrityRequirementLow,
			aReq:      vector.AvailabilityRequirementLow,
			expCRFact: 0.5,
			expIRFact: 0.5,
			expARFact: 0.5,
		},
		{
			name:      "All Medium",
			cReq:      vector.ConfidentialityRequirementMedium,
			iReq:      vector.IntegrityRequirementMedium,
			aReq:      vector.AvailabilityRequirementMedium,
			expCRFact: 1.0,
			expIRFact: 1.0,
			expARFact: 1.0,
		},
		{
			name:      "All High",
			cReq:      vector.ConfidentialityRequirementHigh,
			iReq:      vector.IntegrityRequirementHigh,
			aReq:      vector.AvailabilityRequirementHigh,
			expCRFact: 1.5,
			expIRFact: 1.5,
			expARFact: 1.5,
		},
		{
			name:      "Mixed Requirements",
			cReq:      vector.ConfidentialityRequirementHigh,
			iReq:      vector.IntegrityRequirementMedium,
			aReq:      vector.AvailabilityRequirementLow,
			expCRFact: 1.5,
			expIRFact: 1.0,
			expARFact: 0.5,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cvss := &Cvss3x{
				Cvss3xEnvironmental: &Cvss3xEnvironmental{
					ConfidentialityRequirement: tc.cReq,
					IntegrityRequirement:       tc.iReq,
					AvailabilityRequirement:    tc.aReq,
				},
			}
			calculator := NewCalculator(cvss)

			cReqFactor := calculator.getConfidentialityRequirementFactor()
			iReqFactor := calculator.getIntegrityRequirementFactor()
			aReqFactor := calculator.getAvailabilityRequirementFactor()

			assert.Equal(t, tc.expCRFact, cReqFactor, "Confidentiality requirement factor incorrect")
			assert.Equal(t, tc.expIRFact, iReqFactor, "Integrity requirement factor incorrect")
			assert.Equal(t, tc.expARFact, aReqFactor, "Availability requirement factor incorrect")
		})
	}
}

// 这里不再单独测试各个getModified*函数，因为它们已经在TestGetModifiedVectorScores中得到了测试
// 同样不再重复测试calculateEnvironmentalScore和calculateModifiedImpactSubScore等函数
// 因为它们已经在TestCalculateEnvironmentalScore和TestCalculateEnvironmentalScoreWithExamples中充分测试
