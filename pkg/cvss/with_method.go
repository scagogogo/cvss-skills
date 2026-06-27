package cvss

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/vector"
)

// WithAVMethod 返回修改了 Attack Vector 的副本
// 这是 Cvss3x 上的链式修改方法，返回新对象，不修改原始
func (x *Cvss3x) WithAVMethod(val rune) (*Cvss3x, error) {
	if x == nil {
		return nil, ErrNilReceiver
	}
	v, err := vector.GetAttackVector(val)
	if err != nil {
		return nil, fmt.Errorf("AV: %w", err)
	}
	result := x.Clone()
	result.Cvss3xBase.AttackVector = v
	return result, nil
}

// WithACMethod 返回修改了 Attack Complexity 的副本
func (x *Cvss3x) WithACMethod(val rune) (*Cvss3x, error) {
	if x == nil {
		return nil, ErrNilReceiver
	}
	v, err := vector.GetAttackComplexity(val)
	if err != nil {
		return nil, fmt.Errorf("AC: %w", err)
	}
	result := x.Clone()
	result.Cvss3xBase.AttackComplexity = v
	return result, nil
}

// WithPRMethod 返回修改了 Privileges Required 的副本
func (x *Cvss3x) WithPRMethod(val rune) (*Cvss3x, error) {
	if x == nil {
		return nil, ErrNilReceiver
	}
	v, err := vector.GetPrivilegesRequired(val)
	if err != nil {
		return nil, fmt.Errorf("PR: %w", err)
	}
	result := x.Clone()
	result.Cvss3xBase.PrivilegesRequired = v
	return result, nil
}

// WithUIMethod 返回修改了 User Interaction 的副本
func (x *Cvss3x) WithUIMethod(val rune) (*Cvss3x, error) {
	if x == nil {
		return nil, ErrNilReceiver
	}
	v, err := vector.GetUserInteraction(val)
	if err != nil {
		return nil, fmt.Errorf("UI: %w", err)
	}
	result := x.Clone()
	result.Cvss3xBase.UserInteraction = v
	return result, nil
}

// WithSMethod 返回修改了 Scope 的副本
func (x *Cvss3x) WithSMethod(val rune) (*Cvss3x, error) {
	if x == nil {
		return nil, ErrNilReceiver
	}
	v, err := vector.GetScope(val)
	if err != nil {
		return nil, fmt.Errorf("S: %w", err)
	}
	result := x.Clone()
	result.Cvss3xBase.Scope = v
	return result, nil
}

// WithCMethod 返回修改了 Confidentiality 的副本
func (x *Cvss3x) WithCMethod(val rune) (*Cvss3x, error) {
	if x == nil {
		return nil, ErrNilReceiver
	}
	v, err := vector.GetConfidentiality(val)
	if err != nil {
		return nil, fmt.Errorf("C: %w", err)
	}
	result := x.Clone()
	result.Cvss3xBase.Confidentiality = v
	return result, nil
}

// WithIMethod 返回修改了 Integrity 的副本
func (x *Cvss3x) WithIMethod(val rune) (*Cvss3x, error) {
	if x == nil {
		return nil, ErrNilReceiver
	}
	v, err := vector.GetIntegrity(val)
	if err != nil {
		return nil, fmt.Errorf("I: %w", err)
	}
	result := x.Clone()
	result.Cvss3xBase.Integrity = v
	return result, nil
}

// WithAMethod 返回修改了 Availability 的副本
func (x *Cvss3x) WithAMethod(val rune) (*Cvss3x, error) {
	if x == nil {
		return nil, ErrNilReceiver
	}
	v, err := vector.GetAvailability(val)
	if err != nil {
		return nil, fmt.Errorf("A: %w", err)
	}
	result := x.Clone()
	result.Cvss3xBase.Availability = v
	return result, nil
}

// WithEMethod 返回修改了 Exploit Code Maturity 的副本
func (x *Cvss3x) WithEMethod(val rune) (*Cvss3x, error) {
	if x == nil {
		return nil, ErrNilReceiver
	}
	v, err := vector.GetExploitCodeMaturity(val)
	if err != nil {
		return nil, fmt.Errorf("E: %w", err)
	}
	result := x.Clone()
	if result.Cvss3xTemporal == nil {
		result.Cvss3xTemporal = &Cvss3xTemporal{}
	}
	result.Cvss3xTemporal.ExploitCodeMaturity = v
	return result, nil
}

// WithRLMethod 返回修改了 Remediation Level 的副本
func (x *Cvss3x) WithRLMethod(val rune) (*Cvss3x, error) {
	if x == nil {
		return nil, ErrNilReceiver
	}
	v, err := vector.GetRemediationLevel(val)
	if err != nil {
		return nil, fmt.Errorf("RL: %w", err)
	}
	result := x.Clone()
	if result.Cvss3xTemporal == nil {
		result.Cvss3xTemporal = &Cvss3xTemporal{}
	}
	result.Cvss3xTemporal.RemediationLevel = v
	return result, nil
}

// WithRCMethod 返回修改了 Report Confidence 的副本
func (x *Cvss3x) WithRCMethod(val rune) (*Cvss3x, error) {
	if x == nil {
		return nil, ErrNilReceiver
	}
	v, err := vector.GetReportConfidence(val)
	if err != nil {
		return nil, fmt.Errorf("RC: %w", err)
	}
	result := x.Clone()
	if result.Cvss3xTemporal == nil {
		result.Cvss3xTemporal = &Cvss3xTemporal{}
	}
	result.Cvss3xTemporal.ReportConfidence = v
	return result, nil
}

// WithTemporalMethod 返回修改了全部时间指标的副本
func (x *Cvss3x) WithTemporalMethod(e, rl, rc rune) (*Cvss3x, error) {
	result, err := x.WithEMethod(e)
	if err != nil {
		return nil, err
	}
	result, err = result.WithRLMethod(rl)
	if err != nil {
		return nil, err
	}
	result, err = result.WithRCMethod(rc)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// WithCRMethod 返回修改了 Confidentiality Requirement 的副本
func (x *Cvss3x) WithCRMethod(val rune) (*Cvss3x, error) {
	if x == nil {
		return nil, ErrNilReceiver
	}
	v, err := vector.GetConfidentialityRequirement(val)
	if err != nil {
		return nil, fmt.Errorf("CR: %w", err)
	}
	result := x.Clone()
	if result.Cvss3xEnvironmental == nil {
		result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
	}
	result.Cvss3xEnvironmental.ConfidentialityRequirement = v
	return result, nil
}

// WithIRMethod 返回修改了 Integrity Requirement 的副本
func (x *Cvss3x) WithIRMethod(val rune) (*Cvss3x, error) {
	if x == nil {
		return nil, ErrNilReceiver
	}
	v, err := vector.GetIntegrityRequirement(val)
	if err != nil {
		return nil, fmt.Errorf("IR: %w", err)
	}
	result := x.Clone()
	if result.Cvss3xEnvironmental == nil {
		result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
	}
	result.Cvss3xEnvironmental.IntegrityRequirement = v
	return result, nil
}

// WithARMethod 返回修改了 Availability Requirement 的副本
func (x *Cvss3x) WithARMethod(val rune) (*Cvss3x, error) {
	if x == nil {
		return nil, ErrNilReceiver
	}
	v, err := vector.GetAvailabilityRequirement(val)
	if err != nil {
		return nil, fmt.Errorf("AR: %w", err)
	}
	result := x.Clone()
	if result.Cvss3xEnvironmental == nil {
		result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
	}
	result.Cvss3xEnvironmental.AvailabilityRequirement = v
	return result, nil
}

// WithMAVMethod 返回修改了 Modified Attack Vector 的副本
func (x *Cvss3x) WithMAVMethod(val rune) (*Cvss3x, error) {
	if x == nil {
		return nil, ErrNilReceiver
	}
	v, err := vector.GetModifiedAttackVector(val)
	if err != nil {
		return nil, fmt.Errorf("MAV: %w", err)
	}
	result := x.Clone()
	if result.Cvss3xEnvironmental == nil {
		result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
	}
	result.Cvss3xEnvironmental.ModifiedAttackVector = v
	return result, nil
}

// WithMACMethod 返回修改了 Modified Attack Complexity 的副本
func (x *Cvss3x) WithMACMethod(val rune) (*Cvss3x, error) {
	if x == nil {
		return nil, ErrNilReceiver
	}
	v, err := vector.GetModifiedAttackComplexity(val)
	if err != nil {
		return nil, fmt.Errorf("MAC: %w", err)
	}
	result := x.Clone()
	if result.Cvss3xEnvironmental == nil {
		result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
	}
	result.Cvss3xEnvironmental.ModifiedAttackComplexity = v
	return result, nil
}

// WithMPRMethod 返回修改了 Modified Privileges Required 的副本
func (x *Cvss3x) WithMPRMethod(val rune) (*Cvss3x, error) {
	if x == nil {
		return nil, ErrNilReceiver
	}
	v, err := vector.GetModifiedPrivilegesRequired(val)
	if err != nil {
		return nil, fmt.Errorf("MPR: %w", err)
	}
	result := x.Clone()
	if result.Cvss3xEnvironmental == nil {
		result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
	}
	result.Cvss3xEnvironmental.ModifiedPrivilegesRequired = v
	return result, nil
}

// WithMUIMethod 返回修改了 Modified User Interaction 的副本
func (x *Cvss3x) WithMUIMethod(val rune) (*Cvss3x, error) {
	if x == nil {
		return nil, ErrNilReceiver
	}
	v, err := vector.GetModifiedUserInteraction(val)
	if err != nil {
		return nil, fmt.Errorf("MUI: %w", err)
	}
	result := x.Clone()
	if result.Cvss3xEnvironmental == nil {
		result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
	}
	result.Cvss3xEnvironmental.ModifiedUserInteraction = v
	return result, nil
}

// WithMSMethod 返回修改了 Modified Scope 的副本
func (x *Cvss3x) WithMSMethod(val rune) (*Cvss3x, error) {
	if x == nil {
		return nil, ErrNilReceiver
	}
	v, err := vector.GetModifiedScope(val)
	if err != nil {
		return nil, fmt.Errorf("MS: %w", err)
	}
	result := x.Clone()
	if result.Cvss3xEnvironmental == nil {
		result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
	}
	result.Cvss3xEnvironmental.ModifiedScope = v
	return result, nil
}

// WithMCMethod 返回修改了 Modified Confidentiality 的副本
func (x *Cvss3x) WithMCMethod(val rune) (*Cvss3x, error) {
	if x == nil {
		return nil, ErrNilReceiver
	}
	v, err := vector.GetModifiedConfidentiality(val)
	if err != nil {
		return nil, fmt.Errorf("MC: %w", err)
	}
	result := x.Clone()
	if result.Cvss3xEnvironmental == nil {
		result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
	}
	result.Cvss3xEnvironmental.ModifiedConfidentiality = v
	return result, nil
}

// WithMIMethod 返回修改了 Modified Integrity 的副本
func (x *Cvss3x) WithMIMethod(val rune) (*Cvss3x, error) {
	if x == nil {
		return nil, ErrNilReceiver
	}
	v, err := vector.GetModifiedIntegrity(val)
	if err != nil {
		return nil, fmt.Errorf("MI: %w", err)
	}
	result := x.Clone()
	if result.Cvss3xEnvironmental == nil {
		result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
	}
	result.Cvss3xEnvironmental.ModifiedIntegrity = v
	return result, nil
}

// WithMAMethod 返回修改了 Modified Availability 的副本
func (x *Cvss3x) WithMAMethod(val rune) (*Cvss3x, error) {
	if x == nil {
		return nil, ErrNilReceiver
	}
	v, err := vector.GetModifiedAvailability(val)
	if err != nil {
		return nil, fmt.Errorf("MA: %w", err)
	}
	result := x.Clone()
	if result.Cvss3xEnvironmental == nil {
		result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
	}
	result.Cvss3xEnvironmental.ModifiedAvailability = v
	return result, nil
}

// WithVersionMethod 返回修改了版本号的副本
func (x *Cvss3x) WithVersionMethod(major, minor int) (*Cvss3x, error) {
	if x == nil {
		return nil, ErrNilReceiver
	}
	result := x.Clone()
	result.MajorVersion = major
	result.MinorVersion = minor
	return result, nil
}
