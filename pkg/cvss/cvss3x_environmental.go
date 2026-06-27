package cvss

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/vector"
	"strings"
)

type Cvss3xEnvironmental struct {
	ConfidentialityRequirement vector.Vector
	IntegrityRequirement       vector.Vector
	AvailabilityRequirement    vector.Vector

	ModifiedAttackVector vector.Vector

	ModifiedAttackComplexity vector.Vector

	ModifiedPrivilegesRequired vector.Vector

	ModifiedUserInteraction vector.Vector

	ModifiedScope vector.Vector

	ModifiedConfidentiality vector.Vector

	ModifiedIntegrity vector.Vector

	ModifiedAvailability vector.Vector
}

// Check 校验环境指标的合法性
// 已设置的环境指标必须属于正确的类别（短名称必须匹配对应指标）
func (x *Cvss3xEnvironmental) Check() error {
	// 校验 CIA 需求指标
	if x.ConfidentialityRequirement != nil && x.ConfidentialityRequirement.GetShortName() != "CR" {
		return fmt.Errorf("ConfidentialityRequirement has invalid short name: %s, expected 'CR'", x.ConfidentialityRequirement.GetShortName())
	}
	if x.IntegrityRequirement != nil && x.IntegrityRequirement.GetShortName() != "IR" {
		return fmt.Errorf("IntegrityRequirement has invalid short name: %s, expected 'IR'", x.IntegrityRequirement.GetShortName())
	}
	if x.AvailabilityRequirement != nil && x.AvailabilityRequirement.GetShortName() != "AR" {
		return fmt.Errorf("AvailabilityRequirement has invalid short name: %s, expected 'AR'", x.AvailabilityRequirement.GetShortName())
	}

	// 校验修改后的基础指标
	if x.ModifiedAttackVector != nil && x.ModifiedAttackVector.GetShortName() != "MAV" {
		return fmt.Errorf("ModifiedAttackVector has invalid short name: %s, expected 'MAV'", x.ModifiedAttackVector.GetShortName())
	}
	if x.ModifiedAttackComplexity != nil && x.ModifiedAttackComplexity.GetShortName() != "MAC" {
		return fmt.Errorf("ModifiedAttackComplexity has invalid short name: %s, expected 'MAC'", x.ModifiedAttackComplexity.GetShortName())
	}
	if x.ModifiedPrivilegesRequired != nil && x.ModifiedPrivilegesRequired.GetShortName() != "MPR" {
		return fmt.Errorf("ModifiedPrivilegesRequired has invalid short name: %s, expected 'MPR'", x.ModifiedPrivilegesRequired.GetShortName())
	}
	if x.ModifiedUserInteraction != nil && x.ModifiedUserInteraction.GetShortName() != "MUI" {
		return fmt.Errorf("ModifiedUserInteraction has invalid short name: %s, expected 'MUI'", x.ModifiedUserInteraction.GetShortName())
	}
	if x.ModifiedScope != nil && x.ModifiedScope.GetShortName() != "MS" {
		return fmt.Errorf("ModifiedScope has invalid short name: %s, expected 'MS'", x.ModifiedScope.GetShortName())
	}
	if x.ModifiedConfidentiality != nil && x.ModifiedConfidentiality.GetShortName() != "MC" {
		return fmt.Errorf("ModifiedConfidentiality has invalid short name: %s, expected 'MC'", x.ModifiedConfidentiality.GetShortName())
	}
	if x.ModifiedIntegrity != nil && x.ModifiedIntegrity.GetShortName() != "MI" {
		return fmt.Errorf("ModifiedIntegrity has invalid short name: %s, expected 'MI'", x.ModifiedIntegrity.GetShortName())
	}
	if x.ModifiedAvailability != nil && x.ModifiedAvailability.GetShortName() != "MA" {
		return fmt.Errorf("ModifiedAvailability has invalid short name: %s, expected 'MA'", x.ModifiedAvailability.GetShortName())
	}

	return nil
}

func (x *Cvss3xEnvironmental) String() string {
	slice := make([]string, 0)

	if x.ConfidentialityRequirement != nil {
		slice = append(slice, x.ConfidentialityRequirement.String())
	}

	if x.IntegrityRequirement != nil {
		slice = append(slice, x.IntegrityRequirement.String())
	}

	if x.AvailabilityRequirement != nil {
		slice = append(slice, x.AvailabilityRequirement.String())
	}

	if x.ModifiedAttackVector != nil {
		slice = append(slice, x.ModifiedAttackVector.String())
	}

	if x.ModifiedAttackComplexity != nil {
		slice = append(slice, x.ModifiedAttackComplexity.String())
	}

	if x.ModifiedPrivilegesRequired != nil {
		slice = append(slice, x.ModifiedPrivilegesRequired.String())
	}

	if x.ModifiedUserInteraction != nil {
		slice = append(slice, x.ModifiedUserInteraction.String())
	}

	if x.ModifiedScope != nil {
		slice = append(slice, x.ModifiedScope.String())
	}

	if x.ModifiedConfidentiality != nil {
		slice = append(slice, x.ModifiedConfidentiality.String())
	}

	if x.ModifiedIntegrity != nil {
		slice = append(slice, x.ModifiedIntegrity.String())
	}

	if x.ModifiedAvailability != nil {
		slice = append(slice, x.ModifiedAvailability.String())
	}

	return strings.Join(slice, "/")
}
