package cvss

import (
	"fmt"
	"strings"

	"github.com/scagogogo/cvss-skills/pkg/vector"
)

// DiffEntry 表示两个 Cvss3x 在某个指标上的差异
type DiffEntry struct {
	Metric    string // 指标短名称，如 "AV", "PR"
	V1        string // 第一个向量的值，如 "N"
	V2        string // 第二个向量的值，如 "L"
	V1Long    string // 第一个向量的长名称，如 "Network"
	V2Long    string // 第二个向量的长名称，如 "Local"
}

// String 返回差异的可读表示
func (d DiffEntry) String() string {
	return fmt.Sprintf("%s: %s vs %s", d.Metric, d.V1, d.V2)
}

// Diff 比较两个 Cvss3x 向量，返回所有不同的指标
func (x *Cvss3x) Diff(other *Cvss3x) []DiffEntry {
	if x == nil || other == nil {
		return nil
	}

	var diffs []DiffEntry

	// Base metrics
	basePairs := []struct {
		metric string
		v1     vector.Vector
		v2     vector.Vector
	}{
		{"AV", x.getBaseVector("AV"), other.getBaseVector("AV")},
		{"AC", x.getBaseVector("AC"), other.getBaseVector("AC")},
		{"PR", x.getBaseVector("PR"), other.getBaseVector("PR")},
		{"UI", x.getBaseVector("UI"), other.getBaseVector("UI")},
		{"S", x.getBaseVector("S"), other.getBaseVector("S")},
		{"C", x.getBaseVector("C"), other.getBaseVector("C")},
		{"I", x.getBaseVector("I"), other.getBaseVector("I")},
		{"A", x.getBaseVector("A"), other.getBaseVector("A")},
	}
	diffs = append(diffs, compareVectors(basePairs)...)

	// Temporal metrics
	temporalPairs := []struct {
		metric string
		v1     vector.Vector
		v2     vector.Vector
	}{
		{"E", x.getTemporalVector("E"), other.getTemporalVector("E")},
		{"RL", x.getTemporalVector("RL"), other.getTemporalVector("RL")},
		{"RC", x.getTemporalVector("RC"), other.getTemporalVector("RC")},
	}
	diffs = append(diffs, compareVectors(temporalPairs)...)

	// Environmental metrics
	envPairs := []struct {
		metric string
		v1     vector.Vector
		v2     vector.Vector
	}{
		{"CR", x.getEnvVector("CR"), other.getEnvVector("CR")},
		{"IR", x.getEnvVector("IR"), other.getEnvVector("IR")},
		{"AR", x.getEnvVector("AR"), other.getEnvVector("AR")},
		{"MAV", x.getEnvVector("MAV"), other.getEnvVector("MAV")},
		{"MAC", x.getEnvVector("MAC"), other.getEnvVector("MAC")},
		{"MPR", x.getEnvVector("MPR"), other.getEnvVector("MPR")},
		{"MUI", x.getEnvVector("MUI"), other.getEnvVector("MUI")},
		{"MS", x.getEnvVector("MS"), other.getEnvVector("MS")},
		{"MC", x.getEnvVector("MC"), other.getEnvVector("MC")},
		{"MI", x.getEnvVector("MI"), other.getEnvVector("MI")},
		{"MA", x.getEnvVector("MA"), other.getEnvVector("MA")},
	}
	diffs = append(diffs, compareVectors(envPairs)...)

	return diffs
}

// compareVectors 比较一组向量对，返回不同的条目
func compareVectors(pairs []struct {
	metric string
	v1     vector.Vector
	v2     vector.Vector
}) []DiffEntry {
	var diffs []DiffEntry
	for _, p := range pairs {
		v1Set := p.v1 != nil
		v2Set := p.v2 != nil

		if !v1Set && !v2Set {
			continue // 两者都未设置，相同
		}

		if v1Set != v2Set {
			// 一个设置了另一个没设置
			v1Short, v1Long := "-", "-"
			v2Short, v2Long := "-", "-"
			if v1Set {
				v1Short = string(p.v1.GetShortValue())
				v1Long = p.v1.GetLongValue()
			}
			if v2Set {
				v2Short = string(p.v2.GetShortValue())
				v2Long = p.v2.GetLongValue()
			}
			diffs = append(diffs, DiffEntry{
				Metric: p.metric, V1: v1Short, V2: v2Short,
				V1Long: v1Long, V2Long: v2Long,
			})
			continue
		}

		// 两者都设置了，比较值
		if p.v1.GetShortValue() != p.v2.GetShortValue() {
			diffs = append(diffs, DiffEntry{
				Metric: p.metric,
				V1:     string(p.v1.GetShortValue()),
				V2:     string(p.v2.GetShortValue()),
				V1Long: p.v1.GetLongValue(),
				V2Long: p.v2.GetLongValue(),
			})
		}
	}
	return diffs
}

// getBaseVector 获取基础指标向量
func (x *Cvss3x) getBaseVector(metric string) vector.Vector {
	if x.Cvss3xBase == nil {
		return nil
	}
	switch metric {
	case "AV":
		return x.Cvss3xBase.AttackVector
	case "AC":
		return x.Cvss3xBase.AttackComplexity
	case "PR":
		return x.Cvss3xBase.PrivilegesRequired
	case "UI":
		return x.Cvss3xBase.UserInteraction
	case "S":
		return x.Cvss3xBase.Scope
	case "C":
		return x.Cvss3xBase.Confidentiality
	case "I":
		return x.Cvss3xBase.Integrity
	case "A":
		return x.Cvss3xBase.Availability
	}
	return nil
}

// getTemporalVector 获取时间指标向量
func (x *Cvss3x) getTemporalVector(metric string) vector.Vector {
	if x.Cvss3xTemporal == nil {
		return nil
	}
	switch metric {
	case "E":
		return x.Cvss3xTemporal.ExploitCodeMaturity
	case "RL":
		return x.Cvss3xTemporal.RemediationLevel
	case "RC":
		return x.Cvss3xTemporal.ReportConfidence
	}
	return nil
}

// getEnvVector 获取环境指标向量
func (x *Cvss3x) getEnvVector(metric string) vector.Vector {
	if x.Cvss3xEnvironmental == nil {
		return nil
	}
	switch metric {
	case "CR":
		return x.Cvss3xEnvironmental.ConfidentialityRequirement
	case "IR":
		return x.Cvss3xEnvironmental.IntegrityRequirement
	case "AR":
		return x.Cvss3xEnvironmental.AvailabilityRequirement
	case "MAV":
		return x.Cvss3xEnvironmental.ModifiedAttackVector
	case "MAC":
		return x.Cvss3xEnvironmental.ModifiedAttackComplexity
	case "MPR":
		return x.Cvss3xEnvironmental.ModifiedPrivilegesRequired
	case "MUI":
		return x.Cvss3xEnvironmental.ModifiedUserInteraction
	case "MS":
		return x.Cvss3xEnvironmental.ModifiedScope
	case "MC":
		return x.Cvss3xEnvironmental.ModifiedConfidentiality
	case "MI":
		return x.Cvss3xEnvironmental.ModifiedIntegrity
	case "MA":
		return x.Cvss3xEnvironmental.ModifiedAvailability
	}
	return nil
}

// Merge 将 other 的非空指标合并到当前 Cvss3x 的副本中
// 当前向量中已设置的指标不会被覆盖
// 返回合并后的新 Cvss3x，不修改原始对象
func (x *Cvss3x) Merge(other *Cvss3x) *Cvss3x {
	if x == nil {
		return other.Clone()
	}
	if other == nil {
		return x.Clone()
	}

	result := x.Clone()

	// 合并基础指标（不覆盖已设置的值）
	if other.Cvss3xBase != nil && result.Cvss3xBase != nil {
		if result.Cvss3xBase.AttackVector == nil && other.Cvss3xBase.AttackVector != nil {
			result.Cvss3xBase.AttackVector = other.Cvss3xBase.AttackVector
		}
		if result.Cvss3xBase.AttackComplexity == nil && other.Cvss3xBase.AttackComplexity != nil {
			result.Cvss3xBase.AttackComplexity = other.Cvss3xBase.AttackComplexity
		}
		if result.Cvss3xBase.PrivilegesRequired == nil && other.Cvss3xBase.PrivilegesRequired != nil {
			result.Cvss3xBase.PrivilegesRequired = other.Cvss3xBase.PrivilegesRequired
		}
		if result.Cvss3xBase.UserInteraction == nil && other.Cvss3xBase.UserInteraction != nil {
			result.Cvss3xBase.UserInteraction = other.Cvss3xBase.UserInteraction
		}
		if result.Cvss3xBase.Scope == nil && other.Cvss3xBase.Scope != nil {
			result.Cvss3xBase.Scope = other.Cvss3xBase.Scope
		}
		if result.Cvss3xBase.Confidentiality == nil && other.Cvss3xBase.Confidentiality != nil {
			result.Cvss3xBase.Confidentiality = other.Cvss3xBase.Confidentiality
		}
		if result.Cvss3xBase.Integrity == nil && other.Cvss3xBase.Integrity != nil {
			result.Cvss3xBase.Integrity = other.Cvss3xBase.Integrity
		}
		if result.Cvss3xBase.Availability == nil && other.Cvss3xBase.Availability != nil {
			result.Cvss3xBase.Availability = other.Cvss3xBase.Availability
		}
	}

	// 合并时间指标
	if other.Cvss3xTemporal != nil {
		if result.Cvss3xTemporal == nil {
			result.Cvss3xTemporal = &Cvss3xTemporal{}
		}
		if result.Cvss3xTemporal.ExploitCodeMaturity == nil && other.Cvss3xTemporal.ExploitCodeMaturity != nil {
			result.Cvss3xTemporal.ExploitCodeMaturity = other.Cvss3xTemporal.ExploitCodeMaturity
		}
		if result.Cvss3xTemporal.RemediationLevel == nil && other.Cvss3xTemporal.RemediationLevel != nil {
			result.Cvss3xTemporal.RemediationLevel = other.Cvss3xTemporal.RemediationLevel
		}
		if result.Cvss3xTemporal.ReportConfidence == nil && other.Cvss3xTemporal.ReportConfidence != nil {
			result.Cvss3xTemporal.ReportConfidence = other.Cvss3xTemporal.ReportConfidence
		}
	}

	// 合并环境指标
	if other.Cvss3xEnvironmental != nil {
		if result.Cvss3xEnvironmental == nil {
			result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		if result.Cvss3xEnvironmental.ConfidentialityRequirement == nil && other.Cvss3xEnvironmental.ConfidentialityRequirement != nil {
			result.Cvss3xEnvironmental.ConfidentialityRequirement = other.Cvss3xEnvironmental.ConfidentialityRequirement
		}
		if result.Cvss3xEnvironmental.IntegrityRequirement == nil && other.Cvss3xEnvironmental.IntegrityRequirement != nil {
			result.Cvss3xEnvironmental.IntegrityRequirement = other.Cvss3xEnvironmental.IntegrityRequirement
		}
		if result.Cvss3xEnvironmental.AvailabilityRequirement == nil && other.Cvss3xEnvironmental.AvailabilityRequirement != nil {
			result.Cvss3xEnvironmental.AvailabilityRequirement = other.Cvss3xEnvironmental.AvailabilityRequirement
		}
		if result.Cvss3xEnvironmental.ModifiedAttackVector == nil && other.Cvss3xEnvironmental.ModifiedAttackVector != nil {
			result.Cvss3xEnvironmental.ModifiedAttackVector = other.Cvss3xEnvironmental.ModifiedAttackVector
		}
		if result.Cvss3xEnvironmental.ModifiedAttackComplexity == nil && other.Cvss3xEnvironmental.ModifiedAttackComplexity != nil {
			result.Cvss3xEnvironmental.ModifiedAttackComplexity = other.Cvss3xEnvironmental.ModifiedAttackComplexity
		}
		if result.Cvss3xEnvironmental.ModifiedPrivilegesRequired == nil && other.Cvss3xEnvironmental.ModifiedPrivilegesRequired != nil {
			result.Cvss3xEnvironmental.ModifiedPrivilegesRequired = other.Cvss3xEnvironmental.ModifiedPrivilegesRequired
		}
		if result.Cvss3xEnvironmental.ModifiedUserInteraction == nil && other.Cvss3xEnvironmental.ModifiedUserInteraction != nil {
			result.Cvss3xEnvironmental.ModifiedUserInteraction = other.Cvss3xEnvironmental.ModifiedUserInteraction
		}
		if result.Cvss3xEnvironmental.ModifiedScope == nil && other.Cvss3xEnvironmental.ModifiedScope != nil {
			result.Cvss3xEnvironmental.ModifiedScope = other.Cvss3xEnvironmental.ModifiedScope
		}
		if result.Cvss3xEnvironmental.ModifiedConfidentiality == nil && other.Cvss3xEnvironmental.ModifiedConfidentiality != nil {
			result.Cvss3xEnvironmental.ModifiedConfidentiality = other.Cvss3xEnvironmental.ModifiedConfidentiality
		}
		if result.Cvss3xEnvironmental.ModifiedIntegrity == nil && other.Cvss3xEnvironmental.ModifiedIntegrity != nil {
			result.Cvss3xEnvironmental.ModifiedIntegrity = other.Cvss3xEnvironmental.ModifiedIntegrity
		}
		if result.Cvss3xEnvironmental.ModifiedAvailability == nil && other.Cvss3xEnvironmental.ModifiedAvailability != nil {
			result.Cvss3xEnvironmental.ModifiedAvailability = other.Cvss3xEnvironmental.ModifiedAvailability
		}
	}

	return result
}

// Description 返回 CVSS 向量的人类可读描述
// 格式为 "Attack Vector: Network, Attack Complexity: Low, ..."
func (x *Cvss3x) Description() string {
	if x == nil {
		return ""
	}

	var parts []string

	// 基础指标
	if x.Cvss3xBase != nil {
		baseMetrics := []struct {
			name   string
			vector vector.Vector
		}{
			{"Attack Vector", x.Cvss3xBase.AttackVector},
			{"Attack Complexity", x.Cvss3xBase.AttackComplexity},
			{"Privileges Required", x.Cvss3xBase.PrivilegesRequired},
			{"User Interaction", x.Cvss3xBase.UserInteraction},
			{"Scope", x.Cvss3xBase.Scope},
			{"Confidentiality", x.Cvss3xBase.Confidentiality},
			{"Integrity", x.Cvss3xBase.Integrity},
			{"Availability", x.Cvss3xBase.Availability},
		}
		for _, m := range baseMetrics {
			if m.vector != nil {
				parts = append(parts, fmt.Sprintf("%s: %s", m.name, m.vector.GetLongValue()))
			}
		}
	}

	// 时间指标
	if x.Cvss3xTemporal != nil {
		temporalMetrics := []struct {
			name   string
			vector vector.Vector
		}{
			{"Exploit Code Maturity", x.Cvss3xTemporal.ExploitCodeMaturity},
			{"Remediation Level", x.Cvss3xTemporal.RemediationLevel},
			{"Report Confidence", x.Cvss3xTemporal.ReportConfidence},
		}
		for _, m := range temporalMetrics {
			if m.vector != nil {
				parts = append(parts, fmt.Sprintf("%s: %s", m.name, m.vector.GetLongValue()))
			}
		}
	}

	// 环境指标
	if x.Cvss3xEnvironmental != nil {
		envMetrics := []struct {
			name   string
			vector vector.Vector
		}{
			{"Confidentiality Requirement", x.Cvss3xEnvironmental.ConfidentialityRequirement},
			{"Integrity Requirement", x.Cvss3xEnvironmental.IntegrityRequirement},
			{"Availability Requirement", x.Cvss3xEnvironmental.AvailabilityRequirement},
			{"Modified Attack Vector", x.Cvss3xEnvironmental.ModifiedAttackVector},
			{"Modified Attack Complexity", x.Cvss3xEnvironmental.ModifiedAttackComplexity},
			{"Modified Privileges Required", x.Cvss3xEnvironmental.ModifiedPrivilegesRequired},
			{"Modified User Interaction", x.Cvss3xEnvironmental.ModifiedUserInteraction},
			{"Modified Scope", x.Cvss3xEnvironmental.ModifiedScope},
			{"Modified Confidentiality", x.Cvss3xEnvironmental.ModifiedConfidentiality},
			{"Modified Integrity", x.Cvss3xEnvironmental.ModifiedIntegrity},
			{"Modified Availability", x.Cvss3xEnvironmental.ModifiedAvailability},
		}
		for _, m := range envMetrics {
			if m.vector != nil {
				parts = append(parts, fmt.Sprintf("%s: %s", m.name, m.vector.GetLongValue()))
			}
		}
	}

	return strings.Join(parts, ", ")
}
