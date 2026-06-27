package cvss

import (
	"testing"

	"github.com/scagogogo/cvss-skills/pkg/vector"
)

func TestCalculateEnvironmentalScore(t *testing.T) {
	// Test cases - directly create CVSS objects without parsing
	tests := []struct {
		name     string
		cvss     *Cvss3x
		expected float64
	}{
		{
			name: "Base metrics only - Critical",
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
			name: "Environmental with CIA requirements",
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
				Cvss3xTemporal: &Cvss3xTemporal{
					ExploitCodeMaturity: vector.ExploitCodeMaturityFunctional,
					RemediationLevel:    vector.RemediationLevelOfficialFix,
					ReportConfidence:    vector.ReportConfidenceConfirmed,
				},
				Cvss3xEnvironmental: &Cvss3xEnvironmental{
					ConfidentialityRequirement: vector.ConfidentialityRequirementHigh,
					IntegrityRequirement:       vector.IntegrityRequirementMedium,
					AvailabilityRequirement:    vector.AvailabilityRequirementLow,
				},
			},
			expected: 9.3, // Corrected: now includes temporal multipliers
		},
		{
			name: "Environmental with modified metrics",
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
				Cvss3xTemporal: &Cvss3xTemporal{
					ExploitCodeMaturity: vector.ExploitCodeMaturityFunctional,
					RemediationLevel:    vector.RemediationLevelOfficialFix,
					ReportConfidence:    vector.ReportConfidenceConfirmed,
				},
				Cvss3xEnvironmental: &Cvss3xEnvironmental{
					ModifiedAttackVector:     vector.ModifiedAttackVectorAdjacent,
					ModifiedAttackComplexity: vector.ModifiedAttackComplexityHigh,
				},
			},
			expected: 7.8, // Corrected: now includes temporal multipliers
		},
		{
			name: "Full environmental metrics",
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
				Cvss3xTemporal: &Cvss3xTemporal{
					ExploitCodeMaturity: vector.ExploitCodeMaturityFunctional,
					RemediationLevel:    vector.RemediationLevelOfficialFix,
					ReportConfidence:    vector.ReportConfidenceConfirmed,
				},
				Cvss3xEnvironmental: &Cvss3xEnvironmental{
					ConfidentialityRequirement: vector.ConfidentialityRequirementHigh,
					IntegrityRequirement:       vector.IntegrityRequirementMedium,
					AvailabilityRequirement:    vector.AvailabilityRequirementLow,
					ModifiedAttackVector:       vector.ModifiedAttackVectorAdjacent,
					ModifiedAttackComplexity:   vector.ModifiedAttackComplexityHigh,
					ModifiedPrivilegesRequired: vector.ModifiedPrivilegesRequiredHigh,
					ModifiedUserInteraction:    vector.ModifiedUserInteractionRequired,
					ModifiedScope:              vector.ModifiedScopeUnchanged,
					ModifiedConfidentiality:    vector.ModifiedConfidentialityLow,
					ModifiedIntegrity:          vector.ModifiedIntegrityLow,
					ModifiedAvailability:       vector.ModifiedAvailabilityLow,
				},
			},
			expected: 3.6, // Corrected: now includes temporal multipliers
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calculator := NewCalculator(tt.cvss)
			score, err := calculator.Calculate()
			if err != nil {
				t.Fatalf("Failed to calculate score: %v", err)
			}

			// 精度问题，只比较小数点后1位
			if roundUp(score*10)/10 != tt.expected {
				t.Errorf("Expected score %v, got %v", tt.expected, score)
			}
		})
	}
}

func TestGetModifiedVectorScores(t *testing.T) {
	// 创建一个带有修改后指标的CVSS对象
	cvss := NewCvss3x()
	cvss.MajorVersion = 3
	cvss.MinorVersion = 1

	// 设置基本指标
	cvss.Cvss3xBase = &Cvss3xBase{
		AttackVector:       vector.AttackVectorNetwork,
		AttackComplexity:   vector.AttackComplexityLow,
		PrivilegesRequired: vector.PrivilegesRequiredNone,
		UserInteraction:    vector.UserInteractionNone,
		Scope:              vector.ScopeUnchanged,
		Confidentiality:    vector.ConfidentialityHigh,
		Integrity:          vector.IntegrityHigh,
		Availability:       vector.AvailabilityHigh,
	}

	// 设置环境指标
	cvss.Cvss3xEnvironmental = &Cvss3xEnvironmental{
		ModifiedAttackVector:       vector.ModifiedAttackVectorAdjacent,
		ModifiedAttackComplexity:   vector.ModifiedAttackComplexityHigh,
		ModifiedPrivilegesRequired: vector.ModifiedPrivilegesRequiredLow,
		ModifiedUserInteraction:    vector.ModifiedUserInteractionRequired,
		ModifiedScope:              vector.ModifiedScopeChanged,
		ModifiedConfidentiality:    vector.ModifiedConfidentialityLow,
		ModifiedIntegrity:          vector.ModifiedIntegrityLow,
		ModifiedAvailability:       vector.ModifiedAvailabilityLow,
		ConfidentialityRequirement: vector.ConfidentialityRequirementHigh,
		IntegrityRequirement:       vector.IntegrityRequirementMedium,
		AvailabilityRequirement:    vector.AvailabilityRequirementLow,
	}

	calculator := NewCalculator(cvss)

	// 测试各修改后指标评分获取函数
	t.Run("ModifiedAttackVector", func(t *testing.T) {
		expected := vector.ModifiedAttackVectorAdjacent.GetScore()
		actual := calculator.getModifiedAttackVectorScore()
		if actual != expected {
			t.Errorf("Expected %v, got %v", expected, actual)
		}
	})

	t.Run("ModifiedAttackComplexity", func(t *testing.T) {
		expected := vector.ModifiedAttackComplexityHigh.GetScore()
		actual := calculator.getModifiedAttackComplexityScore()
		if actual != expected {
			t.Errorf("Expected %v, got %v", expected, actual)
		}
	})

	t.Run("ModifiedPrivilegesRequired", func(t *testing.T) {
		// 需要考虑范围改变的情况
		expected := 0.68 // PR:L with scope changed
		actual := calculator.getModifiedPrivilegesRequiredScore()
		if actual != expected {
			t.Errorf("Expected %v, got %v", expected, actual)
		}
	})

	t.Run("ModifiedUserInteraction", func(t *testing.T) {
		expected := vector.ModifiedUserInteractionRequired.GetScore()
		actual := calculator.getModifiedUserInteractionScore()
		if actual != expected {
			t.Errorf("Expected %v, got %v", expected, actual)
		}
	})

	t.Run("isModifiedChangedScope", func(t *testing.T) {
		if !calculator.isModifiedChangedScope() {
			t.Error("Expected modified scope to be changed")
		}
	})

	t.Run("ModifiedConfidentiality", func(t *testing.T) {
		expected := vector.ModifiedConfidentialityLow.GetScore()
		actual := calculator.getModifiedConfidentialityScore()
		if actual != expected {
			t.Errorf("Expected %v, got %v", expected, actual)
		}
	})

	t.Run("RequirementFactors", func(t *testing.T) {
		expectedCR := 1.5 // High
		actualCR := calculator.getConfidentialityRequirementFactor()
		if actualCR != expectedCR {
			t.Errorf("Expected CR factor %v, got %v", expectedCR, actualCR)
		}

		expectedIR := 1.0 // Medium
		actualIR := calculator.getIntegrityRequirementFactor()
		if actualIR != expectedIR {
			t.Errorf("Expected IR factor %v, got %v", expectedIR, actualIR)
		}

		expectedAR := 0.5 // Low
		actualAR := calculator.getAvailabilityRequirementFactor()
		if actualAR != expectedAR {
			t.Errorf("Expected AR factor %v, got %v", expectedAR, actualAR)
		}
	})
}
