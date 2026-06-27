package cvss

import (
	"fmt"
	"testing"

	"github.com/scagogogo/cvss-skills/pkg/vector"
)

func TestDebugEnvironmentalScore(t *testing.T) {
	// 创建一个带有环境指标的CVSS对象
	cvss := NewCvss3x()
	cvss.MajorVersion = 3
	cvss.MinorVersion = 1

	// 设置基本指标
	cvss.Cvss3xBase = &Cvss3xBase{
		AttackVector:       vector.AttackVectorNetwork,
		AttackComplexity:   vector.AttackComplexityLow,
		PrivilegesRequired: vector.PrivilegesRequiredNone,
		UserInteraction:    vector.UserInteractionNone,
		Scope:              vector.ScopeChanged,
		Confidentiality:    vector.ConfidentialityHigh,
		Integrity:          vector.IntegrityHigh,
		Availability:       vector.AvailabilityHigh,
	}

	// 设置时间指标
	cvss.Cvss3xTemporal = &Cvss3xTemporal{
		ExploitCodeMaturity: vector.ExploitCodeMaturityFunctional,
		RemediationLevel:    vector.RemediationLevelOfficialFix,
		ReportConfidence:    vector.ReportConfidenceConfirmed,
	}

	// 设置环境指标 - CIA需求
	cvss.Cvss3xEnvironmental = &Cvss3xEnvironmental{
		ConfidentialityRequirement: vector.ConfidentialityRequirementHigh,
		IntegrityRequirement:       vector.IntegrityRequirementMedium,
		AvailabilityRequirement:    vector.AvailabilityRequirementLow,
		ModifiedAttackVector:       vector.ModifiedAttackVectorAdjacent,
		ModifiedAttackComplexity:   vector.ModifiedAttackComplexityHigh,
	}

	calculator := NewCalculator(cvss)

	// 打印各个计算步骤的值
	fmt.Println("Has Temporal Metrics:", calculator.hasTemporalMetrics())
	fmt.Println("Has Environmental Metrics:", calculator.hasEnvironmentalMetrics())

	// 计算并打印各个得分
	baseScore := calculator.calculateBaseScore()
	fmt.Println("Base Score:", baseScore)

	temporalScore := calculator.calculateTemporalScore(baseScore)
	fmt.Println("Temporal Score:", temporalScore)

	modifiedImpactSubScore := calculator.calculateModifiedImpactSubScore()
	fmt.Println("Modified Impact Sub Score:", modifiedImpactSubScore)

	modifiedExploitabilitySubScore := calculator.calculateModifiedExploitabilitySubScore()
	fmt.Println("Modified Exploitability Sub Score:", modifiedExploitabilitySubScore)

	envScore := calculator.calculateEnvironmentalScore()
	fmt.Println("Environmental Score:", envScore)

	// 打印关键环境计算值
	fmt.Println("\nKey Environmental Calculation Values:")
	fmt.Println("Modified Attack Vector Score:", calculator.getModifiedAttackVectorScore())
	fmt.Println("Modified Attack Complexity Score:", calculator.getModifiedAttackComplexityScore())
	fmt.Println("Modified Privileges Required Score:", calculator.getModifiedPrivilegesRequiredScore())
	fmt.Println("Modified User Interaction Score:", calculator.getModifiedUserInteractionScore())
	fmt.Println("Modified Scope Changed:", calculator.isModifiedChangedScope())

	// 计算最终得分
	finalScore, _ := calculator.Calculate()
	fmt.Println("\nFinal Score:", finalScore)

	// 检查是否与期望值匹配
	if finalScore != envScore {
		t.Errorf("Final score %v does not match environmental score %v", finalScore, envScore)
	}
}
