package cvss

import (
	"testing"

	"github.com/scagogogo/cvss-parser/pkg/vector"
)

func TestCalculateEnvironmentalScoreWithExamples(t *testing.T) {
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
				// 添加时间指标以减小基础分数，这样环境分数的影响会更明显
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
			expected: 9.3, // Corrected: now includes temporal multipliers (E:0.97 × RL:0.95 × RC:1.0)
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
			expected: 7.8, // Corrected: now includes temporal multipliers，修正为8.4 (根据更新后的公式计算)
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
