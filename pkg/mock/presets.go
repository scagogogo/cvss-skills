package mock

import (
	"github.com/scagogogo/cvss-parser/pkg/cvss"
	"github.com/scagogogo/cvss-parser/pkg/vector"
)

// CriticalCvss31 返回一个 CVSS 3.1 Critical 级别的预设向量
// 向量: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H (分数: 10.0)
func CriticalCvss31() *cvss.Cvss3x {
	result := cvss.NewCvss3x()
	result.MajorVersion = 3
	result.MinorVersion = 1
	result.Cvss3xBase = &cvss.Cvss3xBase{
		AttackVector:       vector.AttackVectorNetwork,
		AttackComplexity:   vector.AttackComplexityLow,
		PrivilegesRequired: vector.PrivilegesRequiredNone,
		UserInteraction:    vector.UserInteractionNone,
		Scope:              vector.ScopeChanged,
		Confidentiality:    vector.ConfidentialityHigh,
		Integrity:          vector.IntegrityHigh,
		Availability:       vector.AvailabilityHigh,
	}
	return result
}

// HighCvss31 返回一个 CVSS 3.1 High 级别的预设向量
// 向量: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (分数: 9.8)
func HighCvss31() *cvss.Cvss3x {
	result := cvss.NewCvss3x()
	result.MajorVersion = 3
	result.MinorVersion = 1
	result.Cvss3xBase = &cvss.Cvss3xBase{
		AttackVector:       vector.AttackVectorNetwork,
		AttackComplexity:   vector.AttackComplexityLow,
		PrivilegesRequired: vector.PrivilegesRequiredNone,
		UserInteraction:    vector.UserInteractionNone,
		Scope:              vector.ScopeUnchanged,
		Confidentiality:    vector.ConfidentialityHigh,
		Integrity:          vector.IntegrityHigh,
		Availability:       vector.AvailabilityHigh,
	}
	return result
}

// MediumCvss31 返回一个 CVSS 3.1 Medium 级别的预设向量
// 向量: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N (分数: 6.5)
func MediumCvss31() *cvss.Cvss3x {
	result := cvss.NewCvss3x()
	result.MajorVersion = 3
	result.MinorVersion = 1
	result.Cvss3xBase = &cvss.Cvss3xBase{
		AttackVector:       vector.AttackVectorNetwork,
		AttackComplexity:   vector.AttackComplexityLow,
		PrivilegesRequired: vector.PrivilegesRequiredNone,
		UserInteraction:    vector.UserInteractionNone,
		Scope:              vector.ScopeUnchanged,
		Confidentiality:    vector.ConfidentialityLow,
		Integrity:          vector.IntegrityLow,
		Availability:       vector.AvailabilityNone,
	}
	return result
}

// LowCvss31 返回一个 CVSS 3.1 Low 级别的预设向量
// 向量: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N (分数: 3.7)
func LowCvss31() *cvss.Cvss3x {
	result := cvss.NewCvss3x()
	result.MajorVersion = 3
	result.MinorVersion = 1
	result.Cvss3xBase = &cvss.Cvss3xBase{
		AttackVector:       vector.AttackVectorNetwork,
		AttackComplexity:   vector.AttackComplexityHigh,
		PrivilegesRequired: vector.PrivilegesRequiredNone,
		UserInteraction:    vector.UserInteractionNone,
		Scope:              vector.ScopeUnchanged,
		Confidentiality:    vector.ConfidentialityLow,
		Integrity:          vector.IntegrityNone,
		Availability:       vector.AvailabilityNone,
	}
	return result
}

// NoneCvss31 返回一个 CVSS 3.1 None 级别的预设向量
// 向量: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N (分数: 0.0)
func NoneCvss31() *cvss.Cvss3x {
	result := cvss.NewCvss3x()
	result.MajorVersion = 3
	result.MinorVersion = 1
	result.Cvss3xBase = &cvss.Cvss3xBase{
		AttackVector:       vector.AttackVectorNetwork,
		AttackComplexity:   vector.AttackComplexityLow,
		PrivilegesRequired: vector.PrivilegesRequiredNone,
		UserInteraction:    vector.UserInteractionNone,
		Scope:              vector.ScopeUnchanged,
		Confidentiality:    vector.ConfidentialityNone,
		Integrity:          vector.IntegrityNone,
		Availability:       vector.AvailabilityNone,
	}
	return result
}

// ==================== CVSS 3.0 Presets ====================

// CriticalCvss30 返回一个 CVSS 3.0 Critical 级别的预设向量
// 向量: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H (分数: 10.0)
func CriticalCvss30() *cvss.Cvss3x {
	result := cvss.NewCvss3x()
	result.MajorVersion = 3
	result.MinorVersion = 0
	result.Cvss3xBase = &cvss.Cvss3xBase{
		AttackVector:       vector.AttackVectorNetwork,
		AttackComplexity:   vector.AttackComplexityLow,
		PrivilegesRequired: vector.PrivilegesRequiredNone,
		UserInteraction:    vector.UserInteractionNone,
		Scope:              vector.ScopeChanged,
		Confidentiality:    vector.ConfidentialityHigh,
		Integrity:          vector.IntegrityHigh,
		Availability:       vector.AvailabilityHigh,
	}
	return result
}

// HighCvss30 返回一个 CVSS 3.0 High 级别的预设向量
// 向量: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (分数: 9.8)
func HighCvss30() *cvss.Cvss3x {
	result := cvss.NewCvss3x()
	result.MajorVersion = 3
	result.MinorVersion = 0
	result.Cvss3xBase = &cvss.Cvss3xBase{
		AttackVector:       vector.AttackVectorNetwork,
		AttackComplexity:   vector.AttackComplexityLow,
		PrivilegesRequired: vector.PrivilegesRequiredNone,
		UserInteraction:    vector.UserInteractionNone,
		Scope:              vector.ScopeUnchanged,
		Confidentiality:    vector.ConfidentialityHigh,
		Integrity:          vector.IntegrityHigh,
		Availability:       vector.AvailabilityHigh,
	}
	return result
}

// MediumCvss30 返回一个 CVSS 3.0 Medium 级别的预设向量
// 向量: CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N
func MediumCvss30() *cvss.Cvss3x {
	result := cvss.NewCvss3x()
	result.MajorVersion = 3
	result.MinorVersion = 0
	result.Cvss3xBase = &cvss.Cvss3xBase{
		AttackVector:       vector.AttackVectorNetwork,
		AttackComplexity:   vector.AttackComplexityLow,
		PrivilegesRequired: vector.PrivilegesRequiredNone,
		UserInteraction:    vector.UserInteractionRequired,
		Scope:              vector.ScopeUnchanged,
		Confidentiality:    vector.ConfidentialityLow,
		Integrity:          vector.IntegrityLow,
		Availability:       vector.AvailabilityNone,
	}
	return result
}

// LowCvss30 返回一个 CVSS 3.0 Low 级别的预设向量
// 向量: CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N
func LowCvss30() *cvss.Cvss3x {
	result := cvss.NewCvss3x()
	result.MajorVersion = 3
	result.MinorVersion = 0
	result.Cvss3xBase = &cvss.Cvss3xBase{
		AttackVector:       vector.AttackVectorNetwork,
		AttackComplexity:   vector.AttackComplexityHigh,
		PrivilegesRequired: vector.PrivilegesRequiredNone,
		UserInteraction:    vector.UserInteractionNone,
		Scope:              vector.ScopeUnchanged,
		Confidentiality:    vector.ConfidentialityLow,
		Integrity:          vector.IntegrityNone,
		Availability:       vector.AvailabilityNone,
	}
	return result
}

// NoneCvss30 返回一个 CVSS 3.0 None 级别的预设向量
// 向量: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N (分数: 0.0)
func NoneCvss30() *cvss.Cvss3x {
	result := cvss.NewCvss3x()
	result.MajorVersion = 3
	result.MinorVersion = 0
	result.Cvss3xBase = &cvss.Cvss3xBase{
		AttackVector:       vector.AttackVectorNetwork,
		AttackComplexity:   vector.AttackComplexityLow,
		PrivilegesRequired: vector.PrivilegesRequiredNone,
		UserInteraction:    vector.UserInteractionNone,
		Scope:              vector.ScopeUnchanged,
		Confidentiality:    vector.ConfidentialityNone,
		Integrity:          vector.IntegrityNone,
		Availability:       vector.AvailabilityNone,
	}
	return result
}
