package cvss

import (
	"fmt"

	"github.com/scagogogo/cvss-parser/pkg/vector"
)

// Version 返回 CVSS 版本字符串，如 "3.0" 或 "3.1"
func (x *Cvss3x) Version() string {
	return fmt.Sprintf("%d.%d", x.MajorVersion, x.MinorVersion)
}

// Is30 判断是否为 CVSS 3.0 版本
func (x *Cvss3x) Is30() bool {
	return x.MajorVersion == 3 && x.MinorVersion == 0
}

// Is31 判断是否为 CVSS 3.1 版本
func (x *Cvss3x) Is31() bool {
	return x.MajorVersion == 3 && x.MinorVersion == 1
}

// HasTemporalMetrics 判断是否设置了时间指标
// 只要有任一 Temporal 指标被设置，就返回 true
func (x *Cvss3x) HasTemporalMetrics() bool {
	return x.Cvss3xTemporal != nil &&
		(x.Cvss3xTemporal.ExploitCodeMaturity != nil ||
			x.Cvss3xTemporal.RemediationLevel != nil ||
			x.Cvss3xTemporal.ReportConfidence != nil)
}

// HasEnvironmentalMetrics 判断是否设置了环境指标
// 只要有任一 Environmental 指标被设置，就返回 true
func (x *Cvss3x) HasEnvironmentalMetrics() bool {
	return x.Cvss3xEnvironmental != nil &&
		(x.Cvss3xEnvironmental.ConfidentialityRequirement != nil ||
			x.Cvss3xEnvironmental.IntegrityRequirement != nil ||
			x.Cvss3xEnvironmental.AvailabilityRequirement != nil ||
			x.Cvss3xEnvironmental.ModifiedAttackVector != nil ||
			x.Cvss3xEnvironmental.ModifiedAttackComplexity != nil ||
			x.Cvss3xEnvironmental.ModifiedPrivilegesRequired != nil ||
			x.Cvss3xEnvironmental.ModifiedUserInteraction != nil ||
			x.Cvss3xEnvironmental.ModifiedScope != nil ||
			x.Cvss3xEnvironmental.ModifiedConfidentiality != nil ||
			x.Cvss3xEnvironmental.ModifiedIntegrity != nil ||
			x.Cvss3xEnvironmental.ModifiedAvailability != nil)
}

// Equal 判断两个 Cvss3x 是否相等（所有指标值完全相同）
func (x *Cvss3x) Equal(other *Cvss3x) bool {
	if x == nil || other == nil {
		return x == other
	}
	if x.MajorVersion != other.MajorVersion || x.MinorVersion != other.MinorVersion {
		return false
	}
	if !x.Cvss3xBase.Equal(other.Cvss3xBase) {
		return false
	}
	if !x.Cvss3xTemporal.Equal(other.Cvss3xTemporal) {
		return false
	}
	if !x.Cvss3xEnvironmental.Equal(other.Cvss3xEnvironmental) {
		return false
	}
	return true
}

// Clone 创建 Cvss3x 的深拷贝
func (x *Cvss3x) Clone() *Cvss3x {
	if x == nil {
		return nil
	}
	result := &Cvss3x{
		MajorVersion:        x.MajorVersion,
		MinorVersion:        x.MinorVersion,
		Cvss3xBase:          nil,
		Cvss3xTemporal:      nil,
		Cvss3xEnvironmental: nil,
	}

	// Base — vectors are immutable pointers, safe to copy
	if x.Cvss3xBase != nil {
		result.Cvss3xBase = &Cvss3xBase{
			AttackVector:       x.Cvss3xBase.AttackVector,
			AttackComplexity:   x.Cvss3xBase.AttackComplexity,
			PrivilegesRequired: x.Cvss3xBase.PrivilegesRequired,
			UserInteraction:    x.Cvss3xBase.UserInteraction,
			Scope:              x.Cvss3xBase.Scope,
			Confidentiality:    x.Cvss3xBase.Confidentiality,
			Integrity:          x.Cvss3xBase.Integrity,
			Availability:       x.Cvss3xBase.Availability,
		}
	}

	// Temporal
	if x.Cvss3xTemporal != nil {
		result.Cvss3xTemporal = &Cvss3xTemporal{
			ExploitCodeMaturity: x.Cvss3xTemporal.ExploitCodeMaturity,
			RemediationLevel:    x.Cvss3xTemporal.RemediationLevel,
			ReportConfidence:    x.Cvss3xTemporal.ReportConfidence,
		}
	}

	// Environmental
	if x.Cvss3xEnvironmental != nil {
		result.Cvss3xEnvironmental = &Cvss3xEnvironmental{
			ConfidentialityRequirement:  x.Cvss3xEnvironmental.ConfidentialityRequirement,
			IntegrityRequirement:        x.Cvss3xEnvironmental.IntegrityRequirement,
			AvailabilityRequirement:     x.Cvss3xEnvironmental.AvailabilityRequirement,
			ModifiedAttackVector:        x.Cvss3xEnvironmental.ModifiedAttackVector,
			ModifiedAttackComplexity:    x.Cvss3xEnvironmental.ModifiedAttackComplexity,
			ModifiedPrivilegesRequired:  x.Cvss3xEnvironmental.ModifiedPrivilegesRequired,
			ModifiedUserInteraction:     x.Cvss3xEnvironmental.ModifiedUserInteraction,
			ModifiedScope:               x.Cvss3xEnvironmental.ModifiedScope,
			ModifiedConfidentiality:     x.Cvss3xEnvironmental.ModifiedConfidentiality,
			ModifiedIntegrity:           x.Cvss3xEnvironmental.ModifiedIntegrity,
			ModifiedAvailability:        x.Cvss3xEnvironmental.ModifiedAvailability,
		}
	}

	return result
}

// BaseOnly 返回仅包含基础指标的副本（移除时间和环境指标）
// 常用于比较基础评分与完整评分的差异
func (x *Cvss3x) BaseOnly() *Cvss3x {
	if x == nil {
		return nil
	}
	result := &Cvss3x{
		MajorVersion:        x.MajorVersion,
		MinorVersion:        x.MinorVersion,
		Cvss3xBase:          nil,
		Cvss3xTemporal:      nil,
		Cvss3xEnvironmental: nil,
	}
	if x.Cvss3xBase != nil {
		result.Cvss3xBase = &Cvss3xBase{
			AttackVector:       x.Cvss3xBase.AttackVector,
			AttackComplexity:   x.Cvss3xBase.AttackComplexity,
			PrivilegesRequired: x.Cvss3xBase.PrivilegesRequired,
			UserInteraction:    x.Cvss3xBase.UserInteraction,
			Scope:              x.Cvss3xBase.Scope,
			Confidentiality:    x.Cvss3xBase.Confidentiality,
			Integrity:          x.Cvss3xBase.Integrity,
			Availability:       x.Cvss3xBase.Availability,
		}
	}
	return result
}

// Equal 判断两个 Cvss3xBase 是否相等
func (x *Cvss3xBase) Equal(other *Cvss3xBase) bool {
	if x == nil || other == nil {
		return x == other
	}
	return vectorsEqual(x.AttackVector, other.AttackVector) &&
		vectorsEqual(x.AttackComplexity, other.AttackComplexity) &&
		vectorsEqual(x.PrivilegesRequired, other.PrivilegesRequired) &&
		vectorsEqual(x.UserInteraction, other.UserInteraction) &&
		vectorsEqual(x.Scope, other.Scope) &&
		vectorsEqual(x.Confidentiality, other.Confidentiality) &&
		vectorsEqual(x.Integrity, other.Integrity) &&
		vectorsEqual(x.Availability, other.Availability)
}

// Equal 判断两个 Cvss3xTemporal 是否相等
func (x *Cvss3xTemporal) Equal(other *Cvss3xTemporal) bool {
	if x == nil || other == nil {
		return x == other
	}
	return vectorsEqual(x.ExploitCodeMaturity, other.ExploitCodeMaturity) &&
		vectorsEqual(x.RemediationLevel, other.RemediationLevel) &&
		vectorsEqual(x.ReportConfidence, other.ReportConfidence)
}

// Equal 判断两个 Cvss3xEnvironmental 是否相等
func (x *Cvss3xEnvironmental) Equal(other *Cvss3xEnvironmental) bool {
	if x == nil || other == nil {
		return x == other
	}
	return vectorsEqual(x.ConfidentialityRequirement, other.ConfidentialityRequirement) &&
		vectorsEqual(x.IntegrityRequirement, other.IntegrityRequirement) &&
		vectorsEqual(x.AvailabilityRequirement, other.AvailabilityRequirement) &&
		vectorsEqual(x.ModifiedAttackVector, other.ModifiedAttackVector) &&
		vectorsEqual(x.ModifiedAttackComplexity, other.ModifiedAttackComplexity) &&
		vectorsEqual(x.ModifiedPrivilegesRequired, other.ModifiedPrivilegesRequired) &&
		vectorsEqual(x.ModifiedUserInteraction, other.ModifiedUserInteraction) &&
		vectorsEqual(x.ModifiedScope, other.ModifiedScope) &&
		vectorsEqual(x.ModifiedConfidentiality, other.ModifiedConfidentiality) &&
		vectorsEqual(x.ModifiedIntegrity, other.ModifiedIntegrity) &&
		vectorsEqual(x.ModifiedAvailability, other.ModifiedAvailability)
}

// vectorsEqual 比较两个 Vector 是否相等
func vectorsEqual(a, b vector.Vector) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.GetShortName() == b.GetShortName() && a.GetShortValue() == b.GetShortValue()
}

// IsComplete 判断 Cvss3x 是否包含所有必需的基础指标
// 仅检查 8 个基础指标是否全部设置，不检查版本号或可选指标
func (x *Cvss3x) IsComplete() bool {
	if x == nil || x.Cvss3xBase == nil {
		return false
	}
	return x.Cvss3xBase.AttackVector != nil &&
		x.Cvss3xBase.AttackComplexity != nil &&
		x.Cvss3xBase.PrivilegesRequired != nil &&
		x.Cvss3xBase.UserInteraction != nil &&
		x.Cvss3xBase.Scope != nil &&
		x.Cvss3xBase.Confidentiality != nil &&
		x.Cvss3xBase.Integrity != nil &&
		x.Cvss3xBase.Availability != nil
}
