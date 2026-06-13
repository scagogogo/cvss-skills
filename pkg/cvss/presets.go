package cvss

import (
	"github.com/scagogogo/cvss-parser/pkg/vector"
)

// CriticalV31 返回一个 CVSS 3.1 Critical 级别的预设向量
// 向量: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H (分数: 10.0)
func CriticalV31() *Cvss3x {
	return &Cvss3x{
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
	}
}

// HighV31 返回一个 CVSS 3.1 High 级别的预设向量
// 向量: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (分数: 9.8)
func HighV31() *Cvss3x {
	return &Cvss3x{
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
	}
}

// MediumV31 返回一个 CVSS 3.1 Medium 级别的预设向量
// 向量: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N (分数: 6.5)
func MediumV31() *Cvss3x {
	return &Cvss3x{
		MajorVersion: 3,
		MinorVersion: 1,
		Cvss3xBase: &Cvss3xBase{
			AttackVector:       vector.AttackVectorNetwork,
			AttackComplexity:   vector.AttackComplexityLow,
			PrivilegesRequired: vector.PrivilegesRequiredNone,
			UserInteraction:    vector.UserInteractionNone,
			Scope:              vector.ScopeUnchanged,
			Confidentiality:    vector.ConfidentialityLow,
			Integrity:          vector.IntegrityLow,
			Availability:       vector.AvailabilityNone,
		},
	}
}

// LowV31 返回一个 CVSS 3.1 Low 级别的预设向量
// 向量: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N (分数: 3.7)
func LowV31() *Cvss3x {
	return &Cvss3x{
		MajorVersion: 3,
		MinorVersion: 1,
		Cvss3xBase: &Cvss3xBase{
			AttackVector:       vector.AttackVectorNetwork,
			AttackComplexity:   vector.AttackComplexityHigh,
			PrivilegesRequired: vector.PrivilegesRequiredNone,
			UserInteraction:    vector.UserInteractionNone,
			Scope:              vector.ScopeUnchanged,
			Confidentiality:    vector.ConfidentialityLow,
			Integrity:          vector.IntegrityNone,
			Availability:       vector.AvailabilityNone,
		},
	}
}

// NoneV31 返回一个 CVSS 3.1 None 级别的预设向量
// 向量: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N (分数: 0.0)
func NoneV31() *Cvss3x {
	return &Cvss3x{
		MajorVersion: 3,
		MinorVersion: 1,
		Cvss3xBase: &Cvss3xBase{
			AttackVector:       vector.AttackVectorNetwork,
			AttackComplexity:   vector.AttackComplexityLow,
			PrivilegesRequired: vector.PrivilegesRequiredNone,
			UserInteraction:    vector.UserInteractionNone,
			Scope:              vector.ScopeUnchanged,
			Confidentiality:    vector.ConfidentialityNone,
			Integrity:          vector.IntegrityNone,
			Availability:       vector.AvailabilityNone,
		},
	}
}

// ==================== CVSS 3.0 Presets ====================

// CriticalV30 返回一个 CVSS 3.0 Critical 级别的预设向量
// 向量: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H (分数: 10.0)
func CriticalV30() *Cvss3x {
	return &Cvss3x{
		MajorVersion: 3,
		MinorVersion: 0,
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
	}
}

// HighV30 返回一个 CVSS 3.0 High 级别的预设向量
// 向量: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (分数: 9.8)
func HighV30() *Cvss3x {
	return &Cvss3x{
		MajorVersion: 3,
		MinorVersion: 0,
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
	}
}

// MediumV30 返回一个 CVSS 3.0 Medium 级别的预设向量
// 向量: CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N
func MediumV30() *Cvss3x {
	return &Cvss3x{
		MajorVersion: 3,
		MinorVersion: 0,
		Cvss3xBase: &Cvss3xBase{
			AttackVector:       vector.AttackVectorNetwork,
			AttackComplexity:   vector.AttackComplexityLow,
			PrivilegesRequired: vector.PrivilegesRequiredNone,
			UserInteraction:    vector.UserInteractionRequired,
			Scope:              vector.ScopeUnchanged,
			Confidentiality:    vector.ConfidentialityLow,
			Integrity:          vector.IntegrityLow,
			Availability:       vector.AvailabilityNone,
		},
	}
}

// LowV30 返回一个 CVSS 3.0 Low 级别的预设向量
// 向量: CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N
func LowV30() *Cvss3x {
	return &Cvss3x{
		MajorVersion: 3,
		MinorVersion: 0,
		Cvss3xBase: &Cvss3xBase{
			AttackVector:       vector.AttackVectorNetwork,
			AttackComplexity:   vector.AttackComplexityHigh,
			PrivilegesRequired: vector.PrivilegesRequiredNone,
			UserInteraction:    vector.UserInteractionNone,
			Scope:              vector.ScopeUnchanged,
			Confidentiality:    vector.ConfidentialityLow,
			Integrity:          vector.IntegrityNone,
			Availability:       vector.AvailabilityNone,
		},
	}
}

// NoneV30 返回一个 CVSS 3.0 None 级别的预设向量
// 向量: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N (分数: 0.0)
func NoneV30() *Cvss3x {
	return &Cvss3x{
		MajorVersion: 3,
		MinorVersion: 0,
		Cvss3xBase: &Cvss3xBase{
			AttackVector:       vector.AttackVectorNetwork,
			AttackComplexity:   vector.AttackComplexityLow,
			PrivilegesRequired: vector.PrivilegesRequiredNone,
			UserInteraction:    vector.UserInteractionNone,
			Scope:              vector.ScopeUnchanged,
			Confidentiality:    vector.ConfidentialityNone,
			Integrity:          vector.IntegrityNone,
			Availability:       vector.AvailabilityNone,
		},
	}
}
