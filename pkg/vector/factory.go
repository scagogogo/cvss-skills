package vector

import "fmt"

// GetVectorByShortName 根据短名称和值获取向量对象
func GetVectorByShortName(shortName string, value string) (Vector, error) {
	if len(value) != 1 {
		return nil, fmt.Errorf("invalid vector value: %s (should be a single character)", value)
	}
	shortValue := rune(value[0])

	switch shortName {
	case "AV":
		return GetAttackVector(shortValue)
	case "AC":
		return GetAttackComplexity(shortValue)
	case "PR":
		return GetPrivilegesRequired(shortValue)
	case "UI":
		return GetUserInteraction(shortValue)
	case "S":
		return GetScope(shortValue)
	case "C":
		return GetConfidentiality(shortValue)
	case "I":
		return GetIntegrity(shortValue)
	case "A":
		return GetAvailability(shortValue)
	case "E":
		return GetExploitCodeMaturity(shortValue)
	case "RL":
		return GetRemediationLevel(shortValue)
	case "RC":
		return GetReportConfidence(shortValue)
	case "CR":
		return GetConfidentialityRequirement(shortValue)
	case "IR":
		return GetIntegrityRequirement(shortValue)
	case "AR":
		return GetAvailabilityRequirement(shortValue)
	case "MAV":
		return GetModifiedAttackVector(shortValue)
	case "MAC":
		return GetModifiedAttackComplexity(shortValue)
	case "MPR":
		return GetModifiedPrivilegesRequired(shortValue)
	case "MUI":
		return GetModifiedUserInteraction(shortValue)
	case "MS":
		return GetModifiedScope(shortValue)
	case "MC":
		return GetModifiedConfidentiality(shortValue)
	case "MI":
		return GetModifiedIntegrity(shortValue)
	case "MA":
		return GetModifiedAvailability(shortValue)
	default:
		return nil, fmt.Errorf("unknown vector short name: %s", shortName)
	}
}

// GetAttackVector 获取攻击向量
func GetAttackVector(shortValue rune) (Vector, error) {
	switch shortValue {
	case 'N':
		return AttackVectorNetwork, nil
	case 'A':
		return AttackVectorAdjacent, nil
	case 'L':
		return AttackVectorLocal, nil
	case 'P':
		return AttackVectorPhysical, nil
	default:
		return nil, fmt.Errorf("unknown attack vector value: %c", shortValue)
	}
}

// GetAttackComplexity 获取攻击复杂性
func GetAttackComplexity(shortValue rune) (Vector, error) {
	switch shortValue {
	case 'L':
		return AttackComplexityLow, nil
	case 'H':
		return AttackComplexityHigh, nil
	default:
		return nil, fmt.Errorf("unknown attack complexity value: %c", shortValue)
	}
}

// GetPrivilegesRequired 获取所需权限
func GetPrivilegesRequired(shortValue rune) (Vector, error) {
	switch shortValue {
	case 'N':
		return PrivilegesRequiredNone, nil
	case 'L':
		return PrivilegesRequiredLow, nil
	case 'H':
		return PrivilegesRequiredHigh, nil
	default:
		return nil, fmt.Errorf("unknown privileges required value: %c", shortValue)
	}
}

// GetUserInteraction 获取用户交互
func GetUserInteraction(shortValue rune) (Vector, error) {
	switch shortValue {
	case 'N':
		return UserInteractionNone, nil
	case 'R':
		return UserInteractionRequired, nil
	default:
		return nil, fmt.Errorf("unknown user interaction value: %c", shortValue)
	}
}

// GetScope 获取范围
func GetScope(shortValue rune) (Vector, error) {
	switch shortValue {
	case 'U':
		return ScopeUnchanged, nil
	case 'C':
		return ScopeChanged, nil
	default:
		return nil, fmt.Errorf("unknown scope value: %c", shortValue)
	}
}

// GetConfidentiality 获取机密性
func GetConfidentiality(shortValue rune) (Vector, error) {
	switch shortValue {
	case 'N':
		return ConfidentialityNone, nil
	case 'L':
		return ConfidentialityLow, nil
	case 'H':
		return ConfidentialityHigh, nil
	default:
		return nil, fmt.Errorf("unknown confidentiality value: %c", shortValue)
	}
}

// GetIntegrity 获取完整性
func GetIntegrity(shortValue rune) (Vector, error) {
	switch shortValue {
	case 'N':
		return IntegrityNone, nil
	case 'L':
		return IntegrityLow, nil
	case 'H':
		return IntegrityHigh, nil
	default:
		return nil, fmt.Errorf("unknown integrity value: %c", shortValue)
	}
}

// GetAvailability 获取可用性
func GetAvailability(shortValue rune) (Vector, error) {
	switch shortValue {
	case 'N':
		return AvailabilityNone, nil
	case 'L':
		return AvailabilityLow, nil
	case 'H':
		return AvailabilityHigh, nil
	default:
		return nil, fmt.Errorf("unknown availability value: %c", shortValue)
	}
}

// GetExploitCodeMaturity 获取利用代码成熟度
func GetExploitCodeMaturity(shortValue rune) (Vector, error) {
	switch shortValue {
	case 'X':
		return ExploitCodeMaturityNotDefined, nil
	case 'U':
		return ExploitCodeMaturityUnproven, nil
	case 'P':
		return ExploitCodeMaturityProofOfConcept, nil
	case 'F':
		return ExploitCodeMaturityFunctional, nil
	case 'H':
		return ExploitCodeMaturityHigh, nil
	default:
		return nil, fmt.Errorf("unknown exploit code maturity value: %c", shortValue)
	}
}

// GetRemediationLevel 获取修复级别
func GetRemediationLevel(shortValue rune) (Vector, error) {
	switch shortValue {
	case 'X':
		return RemediationLevelNotDefined, nil
	case 'O':
		return RemediationLevelOfficialFix, nil
	case 'T':
		return RemediationLevelTemporaryFix, nil
	case 'W':
		return RemediationLevelWorkaround, nil
	case 'U':
		return RemediationLevelUnavailable, nil
	default:
		return nil, fmt.Errorf("unknown remediation level value: %c", shortValue)
	}
}

// GetReportConfidence 获取报告可信度
func GetReportConfidence(shortValue rune) (Vector, error) {
	switch shortValue {
	case 'X':
		return ReportConfidenceNotDefined, nil
	case 'U':
		return ReportConfidenceUnknown, nil
	case 'R':
		return ReportConfidenceReasonable, nil
	case 'C':
		return ReportConfidenceConfirmed, nil
	default:
		return nil, fmt.Errorf("unknown report confidence value: %c", shortValue)
	}
}

// GetConfidentialityRequirement 获取机密性需求
func GetConfidentialityRequirement(shortValue rune) (Vector, error) {
	switch shortValue {
	case 'X':
		return ConfidentialityRequirementNotDefined, nil
	case 'L':
		return ConfidentialityRequirementLow, nil
	case 'M':
		return ConfidentialityRequirementMedium, nil
	case 'H':
		return ConfidentialityRequirementHigh, nil
	default:
		return nil, fmt.Errorf("unknown confidentiality requirement value: %c", shortValue)
	}
}

// GetIntegrityRequirement 获取完整性需求
func GetIntegrityRequirement(shortValue rune) (Vector, error) {
	switch shortValue {
	case 'X':
		return IntegrityRequirementNotDefined, nil
	case 'L':
		return IntegrityRequirementLow, nil
	case 'M':
		return IntegrityRequirementMedium, nil
	case 'H':
		return IntegrityRequirementHigh, nil
	default:
		return nil, fmt.Errorf("unknown integrity requirement value: %c", shortValue)
	}
}

// GetAvailabilityRequirement 获取可用性需求
func GetAvailabilityRequirement(shortValue rune) (Vector, error) {
	switch shortValue {
	case 'X':
		return AvailabilityRequirementNotDefined, nil
	case 'L':
		return AvailabilityRequirementLow, nil
	case 'M':
		return AvailabilityRequirementMedium, nil
	case 'H':
		return AvailabilityRequirementHigh, nil
	default:
		return nil, fmt.Errorf("unknown availability requirement value: %c", shortValue)
	}
}

// GetModifiedAttackVector 获取修改后的攻击向量
func GetModifiedAttackVector(shortValue rune) (Vector, error) {
	switch shortValue {
	case 'X':
		return AttackVectorNotDefined, nil
	case 'N':
		return ModifiedAttackVectorNetwork, nil
	case 'A':
		return ModifiedAttackVectorAdjacent, nil
	case 'L':
		return ModifiedAttackVectorLocal, nil
	case 'P':
		return ModifiedAttackVectorPhysical, nil
	default:
		return nil, fmt.Errorf("unknown modified attack vector value: %c", shortValue)
	}
}

// GetModifiedAttackComplexity 获取修改后的攻击复杂性
func GetModifiedAttackComplexity(shortValue rune) (Vector, error) {
	switch shortValue {
	case 'X':
		return AttackComplexityNotDefined, nil
	case 'L':
		return ModifiedAttackComplexityLow, nil
	case 'H':
		return ModifiedAttackComplexityHigh, nil
	default:
		return nil, fmt.Errorf("unknown modified attack complexity value: %c", shortValue)
	}
}

// GetModifiedPrivilegesRequired 获取修改后的所需权限
func GetModifiedPrivilegesRequired(shortValue rune) (Vector, error) {
	switch shortValue {
	case 'X':
		return PrivilegesRequiredNotDefined, nil
	case 'N':
		return ModifiedPrivilegesRequiredNone, nil
	case 'L':
		return ModifiedPrivilegesRequiredLow, nil
	case 'H':
		return ModifiedPrivilegesRequiredHigh, nil
	default:
		return nil, fmt.Errorf("unknown modified privileges required value: %c", shortValue)
	}
}

// GetModifiedUserInteraction 获取修改后的用户交互
func GetModifiedUserInteraction(shortValue rune) (Vector, error) {
	switch shortValue {
	case 'X':
		return UserInteractionNotDefined, nil
	case 'N':
		return ModifiedUserInteractionNone, nil
	case 'R':
		return ModifiedUserInteractionRequired, nil
	default:
		return nil, fmt.Errorf("unknown modified user interaction value: %c", shortValue)
	}
}

// GetModifiedScope 获取修改后的范围
func GetModifiedScope(shortValue rune) (Vector, error) {
	switch shortValue {
	case 'X':
		return ScopeNotDefined, nil
	case 'U':
		return ModifiedScopeUnchanged, nil
	case 'C':
		return ModifiedScopeChanged, nil
	default:
		return nil, fmt.Errorf("unknown modified scope value: %c", shortValue)
	}
}

// GetModifiedConfidentiality 获取修改后的机密性
func GetModifiedConfidentiality(shortValue rune) (Vector, error) {
	switch shortValue {
	case 'X':
		return ConfidentialityNotDefined, nil
	case 'N':
		return ModifiedConfidentialityNone, nil
	case 'L':
		return ModifiedConfidentialityLow, nil
	case 'H':
		return ModifiedConfidentialityHigh, nil
	default:
		return nil, fmt.Errorf("unknown modified confidentiality value: %c", shortValue)
	}
}

// GetModifiedIntegrity 获取修改后的完整性
func GetModifiedIntegrity(shortValue rune) (Vector, error) {
	switch shortValue {
	case 'X':
		return IntegrityNotDefined, nil
	case 'N':
		return ModifiedIntegrityNone, nil
	case 'L':
		return ModifiedIntegrityLow, nil
	case 'H':
		return ModifiedIntegrityHigh, nil
	default:
		return nil, fmt.Errorf("unknown modified integrity value: %c", shortValue)
	}
}

// GetModifiedAvailability 获取修改后的可用性
func GetModifiedAvailability(shortValue rune) (Vector, error) {
	switch shortValue {
	case 'X':
		return AvailabilityNotDefined, nil
	case 'N':
		return ModifiedAvailabilityNone, nil
	case 'L':
		return ModifiedAvailabilityLow, nil
	case 'H':
		return ModifiedAvailabilityHigh, nil
	default:
		return nil, fmt.Errorf("unknown modified availability value: %c", shortValue)
	}
}
