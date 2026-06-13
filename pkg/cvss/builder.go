package cvss

import (
	"fmt"

	"github.com/scagogogo/cvss-parser/pkg/vector"
)

// Cvss3xBuilder 提供 Fluent API 构建 Cvss3x 对象
// 用法: cvss.NewBuilder().Version(3, 1).AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').Build()
type Cvss3xBuilder struct {
	majorVersion int
	minorVersion int
	base         *Cvss3xBase
	temporal     *Cvss3xTemporal
	env          *Cvss3xEnvironmental
	err          error
}

// NewBuilder 创建一个新的 Cvss3xBuilder
func NewBuilder() *Cvss3xBuilder {
	return &Cvss3xBuilder{
		majorVersion: 3,
		minorVersion: 1,
		base:         &Cvss3xBase{},
	}
}

// Version 设置 CVSS 版本号
func (b *Cvss3xBuilder) Version(major, minor int) *Cvss3xBuilder {
	b.majorVersion = major
	b.minorVersion = minor
	return b
}

// --- Base Metrics ---

// AV 设置 Attack Vector
func (b *Cvss3xBuilder) AV(val rune) *Cvss3xBuilder {
	if b.err != nil {
		return b
	}
	v, err := vector.GetAttackVector(val)
	if err != nil {
		b.err = fmt.Errorf("AV: %w", err)
		return b
	}
	b.base.AttackVector = v
	return b
}

// AC 设置 Attack Complexity
func (b *Cvss3xBuilder) AC(val rune) *Cvss3xBuilder {
	if b.err != nil {
		return b
	}
	v, err := vector.GetAttackComplexity(val)
	if err != nil {
		b.err = fmt.Errorf("AC: %w", err)
		return b
	}
	b.base.AttackComplexity = v
	return b
}

// PR 设置 Privileges Required
func (b *Cvss3xBuilder) PR(val rune) *Cvss3xBuilder {
	if b.err != nil {
		return b
	}
	v, err := vector.GetPrivilegesRequired(val)
	if err != nil {
		b.err = fmt.Errorf("PR: %w", err)
		return b
	}
	b.base.PrivilegesRequired = v
	return b
}

// UI 设置 User Interaction
func (b *Cvss3xBuilder) UI(val rune) *Cvss3xBuilder {
	if b.err != nil {
		return b
	}
	v, err := vector.GetUserInteraction(val)
	if err != nil {
		b.err = fmt.Errorf("UI: %w", err)
		return b
	}
	b.base.UserInteraction = v
	return b
}

// S 设置 Scope
func (b *Cvss3xBuilder) S(val rune) *Cvss3xBuilder {
	if b.err != nil {
		return b
	}
	v, err := vector.GetScope(val)
	if err != nil {
		b.err = fmt.Errorf("S: %w", err)
		return b
	}
	b.base.Scope = v
	return b
}

// C 设置 Confidentiality Impact
func (b *Cvss3xBuilder) C(val rune) *Cvss3xBuilder {
	if b.err != nil {
		return b
	}
	v, err := vector.GetConfidentiality(val)
	if err != nil {
		b.err = fmt.Errorf("C: %w", err)
		return b
	}
	b.base.Confidentiality = v
	return b
}

// I 设置 Integrity Impact
func (b *Cvss3xBuilder) I(val rune) *Cvss3xBuilder {
	if b.err != nil {
		return b
	}
	v, err := vector.GetIntegrity(val)
	if err != nil {
		b.err = fmt.Errorf("I: %w", err)
		return b
	}
	b.base.Integrity = v
	return b
}

// A 设置 Availability Impact
func (b *Cvss3xBuilder) A(val rune) *Cvss3xBuilder {
	if b.err != nil {
		return b
	}
	v, err := vector.GetAvailability(val)
	if err != nil {
		b.err = fmt.Errorf("A: %w", err)
		return b
	}
	b.base.Availability = v
	return b
}

// --- Temporal Metrics ---

// E 设置 Exploit Code Maturity
func (b *Cvss3xBuilder) E(val rune) *Cvss3xBuilder {
	if b.err != nil {
		return b
	}
	if b.temporal == nil {
		b.temporal = &Cvss3xTemporal{}
	}
	v, err := vector.GetExploitCodeMaturity(val)
	if err != nil {
		b.err = fmt.Errorf("E: %w", err)
		return b
	}
	b.temporal.ExploitCodeMaturity = v
	return b
}

// RL 设置 Remediation Level
func (b *Cvss3xBuilder) RL(val rune) *Cvss3xBuilder {
	if b.err != nil {
		return b
	}
	if b.temporal == nil {
		b.temporal = &Cvss3xTemporal{}
	}
	v, err := vector.GetRemediationLevel(val)
	if err != nil {
		b.err = fmt.Errorf("RL: %w", err)
		return b
	}
	b.temporal.RemediationLevel = v
	return b
}

// RC 设置 Report Confidence
func (b *Cvss3xBuilder) RC(val rune) *Cvss3xBuilder {
	if b.err != nil {
		return b
	}
	if b.temporal == nil {
		b.temporal = &Cvss3xTemporal{}
	}
	v, err := vector.GetReportConfidence(val)
	if err != nil {
		b.err = fmt.Errorf("RC: %w", err)
		return b
	}
	b.temporal.ReportConfidence = v
	return b
}

// --- Environmental Metrics ---

// CR 设置 Confidentiality Requirement
func (b *Cvss3xBuilder) CR(val rune) *Cvss3xBuilder {
	if b.err != nil {
		return b
	}
	if b.env == nil {
		b.env = &Cvss3xEnvironmental{}
	}
	v, err := vector.GetConfidentialityRequirement(val)
	if err != nil {
		b.err = fmt.Errorf("CR: %w", err)
		return b
	}
	b.env.ConfidentialityRequirement = v
	return b
}

// IR 设置 Integrity Requirement
func (b *Cvss3xBuilder) IR(val rune) *Cvss3xBuilder {
	if b.err != nil {
		return b
	}
	if b.env == nil {
		b.env = &Cvss3xEnvironmental{}
	}
	v, err := vector.GetIntegrityRequirement(val)
	if err != nil {
		b.err = fmt.Errorf("IR: %w", err)
		return b
	}
	b.env.IntegrityRequirement = v
	return b
}

// AR 设置 Availability Requirement
func (b *Cvss3xBuilder) AR(val rune) *Cvss3xBuilder {
	if b.err != nil {
		return b
	}
	if b.env == nil {
		b.env = &Cvss3xEnvironmental{}
	}
	v, err := vector.GetAvailabilityRequirement(val)
	if err != nil {
		b.err = fmt.Errorf("AR: %w", err)
		return b
	}
	b.env.AvailabilityRequirement = v
	return b
}

// MAV 设置 Modified Attack Vector
func (b *Cvss3xBuilder) MAV(val rune) *Cvss3xBuilder {
	if b.err != nil {
		return b
	}
	if b.env == nil {
		b.env = &Cvss3xEnvironmental{}
	}
	v, err := vector.GetModifiedAttackVector(val)
	if err != nil {
		b.err = fmt.Errorf("MAV: %w", err)
		return b
	}
	b.env.ModifiedAttackVector = v
	return b
}

// MAC 设置 Modified Attack Complexity
func (b *Cvss3xBuilder) MAC(val rune) *Cvss3xBuilder {
	if b.err != nil {
		return b
	}
	if b.env == nil {
		b.env = &Cvss3xEnvironmental{}
	}
	v, err := vector.GetModifiedAttackComplexity(val)
	if err != nil {
		b.err = fmt.Errorf("MAC: %w", err)
		return b
	}
	b.env.ModifiedAttackComplexity = v
	return b
}

// MPR 设置 Modified Privileges Required
func (b *Cvss3xBuilder) MPR(val rune) *Cvss3xBuilder {
	if b.err != nil {
		return b
	}
	if b.env == nil {
		b.env = &Cvss3xEnvironmental{}
	}
	v, err := vector.GetModifiedPrivilegesRequired(val)
	if err != nil {
		b.err = fmt.Errorf("MPR: %w", err)
		return b
	}
	b.env.ModifiedPrivilegesRequired = v
	return b
}

// MUI 设置 Modified User Interaction
func (b *Cvss3xBuilder) MUI(val rune) *Cvss3xBuilder {
	if b.err != nil {
		return b
	}
	if b.env == nil {
		b.env = &Cvss3xEnvironmental{}
	}
	v, err := vector.GetModifiedUserInteraction(val)
	if err != nil {
		b.err = fmt.Errorf("MUI: %w", err)
		return b
	}
	b.env.ModifiedUserInteraction = v
	return b
}

// MS 设置 Modified Scope
func (b *Cvss3xBuilder) MS(val rune) *Cvss3xBuilder {
	if b.err != nil {
		return b
	}
	if b.env == nil {
		b.env = &Cvss3xEnvironmental{}
	}
	v, err := vector.GetModifiedScope(val)
	if err != nil {
		b.err = fmt.Errorf("MS: %w", err)
		return b
	}
	b.env.ModifiedScope = v
	return b
}

// MC 设置 Modified Confidentiality Impact
func (b *Cvss3xBuilder) MC(val rune) *Cvss3xBuilder {
	if b.err != nil {
		return b
	}
	if b.env == nil {
		b.env = &Cvss3xEnvironmental{}
	}
	v, err := vector.GetModifiedConfidentiality(val)
	if err != nil {
		b.err = fmt.Errorf("MC: %w", err)
		return b
	}
	b.env.ModifiedConfidentiality = v
	return b
}

// MI 设置 Modified Integrity Impact
func (b *Cvss3xBuilder) MI(val rune) *Cvss3xBuilder {
	if b.err != nil {
		return b
	}
	if b.env == nil {
		b.env = &Cvss3xEnvironmental{}
	}
	v, err := vector.GetModifiedIntegrity(val)
	if err != nil {
		b.err = fmt.Errorf("MI: %w", err)
		return b
	}
	b.env.ModifiedIntegrity = v
	return b
}

// MA 设置 Modified Availability Impact
func (b *Cvss3xBuilder) MA(val rune) *Cvss3xBuilder {
	if b.err != nil {
		return b
	}
	if b.env == nil {
		b.env = &Cvss3xEnvironmental{}
	}
	v, err := vector.GetModifiedAvailability(val)
	if err != nil {
		b.err = fmt.Errorf("MA: %w", err)
		return b
	}
	b.env.ModifiedAvailability = v
	return b
}

// Build 构建并返回 Cvss3x 对象
// 如果任何指标值无效或基础指标不完整，返回错误
func (b *Cvss3xBuilder) Build() (*Cvss3x, error) {
	if b.err != nil {
		return nil, b.err
	}

	result := &Cvss3x{
		MajorVersion:        b.majorVersion,
		MinorVersion:        b.minorVersion,
		Cvss3xBase:          b.base,
		Cvss3xTemporal:      b.temporal,
		Cvss3xEnvironmental: b.env,
	}

	return result, nil
}

// BuildChecked 构建并返回 Cvss3x 对象，同时验证基础指标是否完整
// 如果任何指标值无效、版本不支持或基础指标不完整，返回错误
func (b *Cvss3xBuilder) BuildChecked() (*Cvss3x, error) {
	result, err := b.Build()
	if err != nil {
		return nil, err
	}

	// 验证版本
	if result.MajorVersion != 3 {
		return nil, fmt.Errorf("unsupported major version %d, only 3 is supported", result.MajorVersion)
	}
	if result.MinorVersion != 0 && result.MinorVersion != 1 {
		return nil, fmt.Errorf("unsupported minor version %d, only 3.0 and 3.1 are supported", result.MinorVersion)
	}

	// 验证基础指标完整性
	if !result.IsComplete() {
		missing := result.MissingMetrics()
		return nil, fmt.Errorf("incomplete base metrics, missing: %v", missing)
	}

	return result, nil
}

// MustBuild 构建并返回 Cvss3x 对象，如果出错则 panic
func (b *Cvss3xBuilder) MustBuild() *Cvss3x {
	result, err := b.Build()
	if err != nil {
		panic(err)
	}
	return result
}
