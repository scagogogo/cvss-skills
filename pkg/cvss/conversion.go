package cvss

import (
	"fmt"

	"github.com/scagogogo/cvss-parser/pkg/vector"
)

// ConvertToVersion 将 CVSS 向量从一个版本转换到另一个版本
// 目前支持 3.0 ↔ 3.1 的转换
// 注意：UI:Required 在 v3.0 中分数为 0.56，在 v3.1 中为 0.62
// 此方法只修改版本号，不改变指标值，但评分计算会自动适配
//
// 用法:
//
//	v30 := cv.ConvertToVersion(3, 0)  // 转为 v3.0
//	v31 := v30.ConvertToVersion(3, 1) // 转回 v3.1
func (x *Cvss3x) ConvertToVersion(major, minor int) (*Cvss3x, error) {
	if x == nil {
		return nil, ErrNilReceiver
	}
	if major != 3 || (minor != 0 && minor != 1) {
		return nil, fmt.Errorf("unsupported version: %d.%d (only 3.0 and 3.1 supported)", major, minor)
	}

	result := x.Clone()
	result.MajorVersion = major
	result.MinorVersion = minor
	return result, nil
}

// UpgradeTo31 将 v3.0 向量升级为 v3.1
// 便利方法，等价于 ConvertToVersion(3, 1)
func (x *Cvss3x) UpgradeTo31() (*Cvss3x, error) {
	return x.ConvertToVersion(3, 1)
}

// DowngradeTo30 将 v3.1 向量降级为 v3.0
// 便利方法，等价于 ConvertToVersion(3, 0)
func (x *Cvss3x) DowngradeTo30() (*Cvss3x, error) {
	return x.ConvertToVersion(3, 0)
}

// MetricGroup 表示指标组
type MetricGroup struct {
	Name    string            // 组名：Base, Temporal, Environmental
	Metrics []MetricValuePair // 指标-值对
}

// MetricValuePair 表示一个指标-值对
type MetricValuePair struct {
	ShortName string // 指标短名称
	LongName  string // 指标长名称
	Value     string // 短值
	LongValue string // 长值
}

// String 返回指标组的可读表示
func (mg MetricGroup) String() string {
	s := fmt.Sprintf("[%s]\n", mg.Name)
	for _, m := range mg.Metrics {
		s += fmt.Sprintf("  %s:%s (%s = %s)\n", m.ShortName, m.Value, m.LongName, m.LongValue)
	}
	return s
}

// GetMetricGroups 将 Cvss3x 拆分为指标组
//
// 用法:
//
//	groups := cv.GetMetricGroups()
//	for _, g := range groups {
//	    fmt.Println(g.String())
//	}
func (x *Cvss3x) GetMetricGroups() []MetricGroup {
	if x == nil {
		return nil
	}

	var groups []MetricGroup

	// Base metrics
	base := MetricGroup{Name: "Base"}
	if x.Cvss3xBase != nil {
		base.Metrics = append(base.Metrics,
			mv("AV", "Attack Vector", x.Cvss3xBase.AttackVector),
			mv("AC", "Attack Complexity", x.Cvss3xBase.AttackComplexity),
			mv("PR", "Privileges Required", x.Cvss3xBase.PrivilegesRequired),
			mv("UI", "User Interaction", x.Cvss3xBase.UserInteraction),
			mv("S", "Scope", x.Cvss3xBase.Scope),
			mv("C", "Confidentiality", x.Cvss3xBase.Confidentiality),
			mv("I", "Integrity", x.Cvss3xBase.Integrity),
			mv("A", "Availability", x.Cvss3xBase.Availability),
		)
	}
	groups = append(groups, base)

	// Temporal metrics
	if x.HasTemporalMetrics() {
		temporal := MetricGroup{Name: "Temporal"}
		temporal.Metrics = append(temporal.Metrics,
			mv("E", "Exploit Code Maturity", x.Cvss3xTemporal.ExploitCodeMaturity),
			mv("RL", "Remediation Level", x.Cvss3xTemporal.RemediationLevel),
			mv("RC", "Report Confidence", x.Cvss3xTemporal.ReportConfidence),
		)
		groups = append(groups, temporal)
	}

	// Environmental metrics
	if x.HasEnvironmentalMetrics() {
		env := MetricGroup{Name: "Environmental"}
		env.Metrics = append(env.Metrics,
			mv("CR", "Confidentiality Requirement", x.Cvss3xEnvironmental.ConfidentialityRequirement),
			mv("IR", "Integrity Requirement", x.Cvss3xEnvironmental.IntegrityRequirement),
			mv("AR", "Availability Requirement", x.Cvss3xEnvironmental.AvailabilityRequirement),
			mv("MAV", "Modified Attack Vector", x.Cvss3xEnvironmental.ModifiedAttackVector),
			mv("MAC", "Modified Attack Complexity", x.Cvss3xEnvironmental.ModifiedAttackComplexity),
			mv("MPR", "Modified Privileges Required", x.Cvss3xEnvironmental.ModifiedPrivilegesRequired),
			mv("MUI", "Modified User Interaction", x.Cvss3xEnvironmental.ModifiedUserInteraction),
			mv("MS", "Modified Scope", x.Cvss3xEnvironmental.ModifiedScope),
			mv("MC", "Modified Confidentiality", x.Cvss3xEnvironmental.ModifiedConfidentiality),
			mv("MI", "Modified Integrity", x.Cvss3xEnvironmental.ModifiedIntegrity),
			mv("MA", "Modified Availability", x.Cvss3xEnvironmental.ModifiedAvailability),
		)
		groups = append(groups, env)
	}

	return groups
}

// mv 创建 MetricValuePair 从 vector.Vector
func mv(shortName, longName string, v vector.Vector) MetricValuePair {
	if v == nil {
		return MetricValuePair{ShortName: shortName, LongName: longName}
	}
	return MetricValuePair{
		ShortName: shortName,
		LongName:  longName,
		Value:     string(v.GetShortValue()),
		LongValue: v.GetLongValue(),
	}
}

// GetBaseVectorString 返回仅包含基础指标的向量字符串
func (x *Cvss3x) GetBaseVectorString() string {
	if x == nil || x.Cvss3xBase == nil {
		return ""
	}
	return fmt.Sprintf("CVSS:%s/%s", x.Version(), x.Cvss3xBase.String())
}

// GetTemporalVectorString 返回包含基础+时间指标的向量字符串
func (x *Cvss3x) GetTemporalVectorString() string {
	if x == nil {
		return ""
	}
	base := x.GetBaseVectorString()
	if x.Cvss3xTemporal == nil {
		return base
	}
	temporal := x.Cvss3xTemporal.String()
	if temporal == "" {
		return base
	}
	return base + "/" + temporal
}

// GetEnvironmentalVectorString 返回完整的向量字符串（等价于 String()）
func (x *Cvss3x) GetEnvironmentalVectorString() string {
	return x.String()
}
