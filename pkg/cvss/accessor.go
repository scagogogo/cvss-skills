package cvss

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/vector"
)

// GetMetricValue 通过指标短名称获取当前值
// 返回短值字符和长值字符串
//
// 用法:
//
//	shortVal, longVal, _ := cv.GetMetricValue("AV")
//	// shortVal = 'N', longVal = "Network"
func (x *Cvss3x) GetMetricValue(shortName string) (rune, string, error) {
	if x == nil {
		return 0, "", ErrNilReceiver
	}

	v, err := x.getVectorByShortName(shortName)
	if err != nil {
		return 0, "", err
	}
	return v.GetShortValue(), v.GetLongValue(), nil
}

// SetMetricValue 通过指标短名称设置值
// 返回修改后的副本，原始对象不变
//
// 用法:
//
//	modified, _ := cv.SetMetricValue("AV", 'L')
//	fmt.Println(modified.String())
func (x *Cvss3x) SetMetricValue(shortName string, value rune) (*Cvss3x, error) {
	if x == nil {
		return nil, ErrNilReceiver
	}

	result := x.Clone()

	// 根据 shortName 找到要修改的字段
	switch shortName {
	case "AV":
		v, err := vector.GetAttackVector(value)
		if err != nil {
			return nil, fmt.Errorf("AV: %w", err)
		}
		result.Cvss3xBase.AttackVector = v
	case "AC":
		v, err := vector.GetAttackComplexity(value)
		if err != nil {
			return nil, fmt.Errorf("AC: %w", err)
		}
		result.Cvss3xBase.AttackComplexity = v
	case "PR":
		v, err := vector.GetPrivilegesRequired(value)
		if err != nil {
			return nil, fmt.Errorf("PR: %w", err)
		}
		result.Cvss3xBase.PrivilegesRequired = v
	case "UI":
		v, err := vector.GetUserInteraction(value)
		if err != nil {
			return nil, fmt.Errorf("UI: %w", err)
		}
		result.Cvss3xBase.UserInteraction = v
	case "S":
		v, err := vector.GetScope(value)
		if err != nil {
			return nil, fmt.Errorf("S: %w", err)
		}
		result.Cvss3xBase.Scope = v
	case "C":
		v, err := vector.GetConfidentiality(value)
		if err != nil {
			return nil, fmt.Errorf("C: %w", err)
		}
		result.Cvss3xBase.Confidentiality = v
	case "I":
		v, err := vector.GetIntegrity(value)
		if err != nil {
			return nil, fmt.Errorf("I: %w", err)
		}
		result.Cvss3xBase.Integrity = v
	case "A":
		v, err := vector.GetAvailability(value)
		if err != nil {
			return nil, fmt.Errorf("A: %w", err)
		}
		result.Cvss3xBase.Availability = v
	case "E":
		if result.Cvss3xTemporal == nil {
			result.Cvss3xTemporal = &Cvss3xTemporal{}
		}
		v, err := vector.GetExploitCodeMaturity(value)
		if err != nil {
			return nil, fmt.Errorf("E: %w", err)
		}
		result.Cvss3xTemporal.ExploitCodeMaturity = v
	case "RL":
		if result.Cvss3xTemporal == nil {
			result.Cvss3xTemporal = &Cvss3xTemporal{}
		}
		v, err := vector.GetRemediationLevel(value)
		if err != nil {
			return nil, fmt.Errorf("RL: %w", err)
		}
		result.Cvss3xTemporal.RemediationLevel = v
	case "RC":
		if result.Cvss3xTemporal == nil {
			result.Cvss3xTemporal = &Cvss3xTemporal{}
		}
		v, err := vector.GetReportConfidence(value)
		if err != nil {
			return nil, fmt.Errorf("RC: %w", err)
		}
		result.Cvss3xTemporal.ReportConfidence = v
	case "CR":
		if result.Cvss3xEnvironmental == nil {
			result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		v, err := vector.GetConfidentialityRequirement(value)
		if err != nil {
			return nil, fmt.Errorf("CR: %w", err)
		}
		result.Cvss3xEnvironmental.ConfidentialityRequirement = v
	case "IR":
		if result.Cvss3xEnvironmental == nil {
			result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		v, err := vector.GetIntegrityRequirement(value)
		if err != nil {
			return nil, fmt.Errorf("IR: %w", err)
		}
		result.Cvss3xEnvironmental.IntegrityRequirement = v
	case "AR":
		if result.Cvss3xEnvironmental == nil {
			result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		v, err := vector.GetAvailabilityRequirement(value)
		if err != nil {
			return nil, fmt.Errorf("AR: %w", err)
		}
		result.Cvss3xEnvironmental.AvailabilityRequirement = v
	case "MAV":
		if result.Cvss3xEnvironmental == nil {
			result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		v, err := vector.GetModifiedAttackVector(value)
		if err != nil {
			return nil, fmt.Errorf("MAV: %w", err)
		}
		result.Cvss3xEnvironmental.ModifiedAttackVector = v
	case "MAC":
		if result.Cvss3xEnvironmental == nil {
			result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		v, err := vector.GetModifiedAttackComplexity(value)
		if err != nil {
			return nil, fmt.Errorf("MAC: %w", err)
		}
		result.Cvss3xEnvironmental.ModifiedAttackComplexity = v
	case "MPR":
		if result.Cvss3xEnvironmental == nil {
			result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		v, err := vector.GetModifiedPrivilegesRequired(value)
		if err != nil {
			return nil, fmt.Errorf("MPR: %w", err)
		}
		result.Cvss3xEnvironmental.ModifiedPrivilegesRequired = v
	case "MUI":
		if result.Cvss3xEnvironmental == nil {
			result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		v, err := vector.GetModifiedUserInteraction(value)
		if err != nil {
			return nil, fmt.Errorf("MUI: %w", err)
		}
		result.Cvss3xEnvironmental.ModifiedUserInteraction = v
	case "MS":
		if result.Cvss3xEnvironmental == nil {
			result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		v, err := vector.GetModifiedScope(value)
		if err != nil {
			return nil, fmt.Errorf("MS: %w", err)
		}
		result.Cvss3xEnvironmental.ModifiedScope = v
	case "MC":
		if result.Cvss3xEnvironmental == nil {
			result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		v, err := vector.GetModifiedConfidentiality(value)
		if err != nil {
			return nil, fmt.Errorf("MC: %w", err)
		}
		result.Cvss3xEnvironmental.ModifiedConfidentiality = v
	case "MI":
		if result.Cvss3xEnvironmental == nil {
			result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		v, err := vector.GetModifiedIntegrity(value)
		if err != nil {
			return nil, fmt.Errorf("MI: %w", err)
		}
		result.Cvss3xEnvironmental.ModifiedIntegrity = v
	case "MA":
		if result.Cvss3xEnvironmental == nil {
			result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		v, err := vector.GetModifiedAvailability(value)
		if err != nil {
			return nil, fmt.Errorf("MA: %w", err)
		}
		result.Cvss3xEnvironmental.ModifiedAvailability = v
	default:
		return nil, fmt.Errorf("unknown metric: %s", shortName)
	}

	return result, nil
}

// getVectorByShortName 内部辅助：通过短名称获取 vector.Vector
func (x *Cvss3x) getVectorByShortName(shortName string) (vector.Vector, error) {
	switch shortName {
	case "AV":
		return x.Cvss3xBase.AttackVector, nil
	case "AC":
		return x.Cvss3xBase.AttackComplexity, nil
	case "PR":
		return x.Cvss3xBase.PrivilegesRequired, nil
	case "UI":
		return x.Cvss3xBase.UserInteraction, nil
	case "S":
		return x.Cvss3xBase.Scope, nil
	case "C":
		return x.Cvss3xBase.Confidentiality, nil
	case "I":
		return x.Cvss3xBase.Integrity, nil
	case "A":
		return x.Cvss3xBase.Availability, nil
	case "E":
		if x.Cvss3xTemporal == nil {
			return nil, fmt.Errorf("no temporal metrics")
		}
		return x.Cvss3xTemporal.ExploitCodeMaturity, nil
	case "RL":
		if x.Cvss3xTemporal == nil {
			return nil, fmt.Errorf("no temporal metrics")
		}
		return x.Cvss3xTemporal.RemediationLevel, nil
	case "RC":
		if x.Cvss3xTemporal == nil {
			return nil, fmt.Errorf("no temporal metrics")
		}
		return x.Cvss3xTemporal.ReportConfidence, nil
	case "CR":
		if x.Cvss3xEnvironmental == nil {
			return nil, fmt.Errorf("no environmental metrics")
		}
		return x.Cvss3xEnvironmental.ConfidentialityRequirement, nil
	case "IR":
		if x.Cvss3xEnvironmental == nil {
			return nil, fmt.Errorf("no environmental metrics")
		}
		return x.Cvss3xEnvironmental.IntegrityRequirement, nil
	case "AR":
		if x.Cvss3xEnvironmental == nil {
			return nil, fmt.Errorf("no environmental metrics")
		}
		return x.Cvss3xEnvironmental.AvailabilityRequirement, nil
	case "MAV":
		if x.Cvss3xEnvironmental == nil {
			return nil, fmt.Errorf("no environmental metrics")
		}
		return x.Cvss3xEnvironmental.ModifiedAttackVector, nil
	case "MAC":
		if x.Cvss3xEnvironmental == nil {
			return nil, fmt.Errorf("no environmental metrics")
		}
		return x.Cvss3xEnvironmental.ModifiedAttackComplexity, nil
	case "MPR":
		if x.Cvss3xEnvironmental == nil {
			return nil, fmt.Errorf("no environmental metrics")
		}
		return x.Cvss3xEnvironmental.ModifiedPrivilegesRequired, nil
	case "MUI":
		if x.Cvss3xEnvironmental == nil {
			return nil, fmt.Errorf("no environmental metrics")
		}
		return x.Cvss3xEnvironmental.ModifiedUserInteraction, nil
	case "MS":
		if x.Cvss3xEnvironmental == nil {
			return nil, fmt.Errorf("no environmental metrics")
		}
		return x.Cvss3xEnvironmental.ModifiedScope, nil
	case "MC":
		if x.Cvss3xEnvironmental == nil {
			return nil, fmt.Errorf("no environmental metrics")
		}
		return x.Cvss3xEnvironmental.ModifiedConfidentiality, nil
	case "MI":
		if x.Cvss3xEnvironmental == nil {
			return nil, fmt.Errorf("no environmental metrics")
		}
		return x.Cvss3xEnvironmental.ModifiedIntegrity, nil
	case "MA":
		if x.Cvss3xEnvironmental == nil {
			return nil, fmt.Errorf("no environmental metrics")
		}
		return x.Cvss3xEnvironmental.ModifiedAvailability, nil
	default:
		return nil, fmt.Errorf("unknown metric: %s", shortName)
	}
}
