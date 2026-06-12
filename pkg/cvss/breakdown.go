package cvss

import (
	"fmt"

	"github.com/scagogogo/cvss-parser/pkg/vector"
)

// MetricScore 表示单个指标的有效分数
type MetricScore struct {
	ShortName string  // 指标短名称，如 "AV", "PR", "E"
	LongName  string  // 指标长名称，如 "Attack Vector"
	Value     string  // 指标值，如 "N", "L"
	Score     float64 // 有效分数（考虑 Scope/Version 等上下文）
}

// String 返回指标分数的可读表示
func (m MetricScore) String() string {
	return fmt.Sprintf("%s:%s=%.2f", m.ShortName, m.Value, m.Score)
}

// ScoreBreakdown 包含所有指标的详细分数分解
type ScoreBreakdown struct {
	// 基础指标分数
	AttackVector       MetricScore
	AttackComplexity   MetricScore
	PrivilegesRequired MetricScore
	UserInteraction    MetricScore
	Scope              MetricScore
	Confidentiality    MetricScore
	Integrity          MetricScore
	Availability       MetricScore

	// 时间指标分数（仅当设置时有效）
	ExploitCodeMaturity MetricScore
	RemediationLevel    MetricScore
	ReportConfidence    MetricScore

	// 环境需求因子
	ConfidentialityRequirement MetricScore
	IntegrityRequirement       MetricScore
	AvailabilityRequirement    MetricScore

	// 修改后的指标分数
	ModifiedAttackVector       MetricScore
	ModifiedAttackComplexity   MetricScore
	ModifiedPrivilegesRequired MetricScore
	ModifiedUserInteraction    MetricScore
	ModifiedScope              MetricScore
	ModifiedConfidentiality    MetricScore
	ModifiedIntegrity          MetricScore
	ModifiedAvailability       MetricScore
}

// GetScoreBreakdown 返回每个指标的有效分数分解
// 包括考虑 Scope 上下文（PR）和版本上下文（UI）的调整后分数
func (c *Calculator) GetScoreBreakdown() (*ScoreBreakdown, error) {
	if err := c.cvss.Check(); err != nil {
		return nil, err
	}

	b := &ScoreBreakdown{}
	cv := c.cvss

	// 基础指标
	scopeChanged := c.isChangedScope()
	b.AttackVector = makeMetricScore(cv.Cvss3xBase.AttackVector)
	b.AttackComplexity = makeMetricScore(cv.Cvss3xBase.AttackComplexity)
	b.PrivilegesRequired = makeMetricScoreWithScore(cv.Cvss3xBase.PrivilegesRequired,
		vector.GetPrivilegesRequiredScore(cv.Cvss3xBase.PrivilegesRequired, scopeChanged))
	b.UserInteraction = makeMetricScoreWithScore(cv.Cvss3xBase.UserInteraction,
		vector.GetUserInteractionScore(cv.Cvss3xBase.UserInteraction, cv.MinorVersion))
	b.Scope = makeMetricScore(cv.Cvss3xBase.Scope)
	b.Confidentiality = makeMetricScore(cv.Cvss3xBase.Confidentiality)
	b.Integrity = makeMetricScore(cv.Cvss3xBase.Integrity)
	b.Availability = makeMetricScore(cv.Cvss3xBase.Availability)

	// 时间指标
	if cv.Cvss3xTemporal != nil {
		if cv.Cvss3xTemporal.ExploitCodeMaturity != nil {
			b.ExploitCodeMaturity = makeMetricScore(cv.Cvss3xTemporal.ExploitCodeMaturity)
		}
		if cv.Cvss3xTemporal.RemediationLevel != nil {
			b.RemediationLevel = makeMetricScore(cv.Cvss3xTemporal.RemediationLevel)
		}
		if cv.Cvss3xTemporal.ReportConfidence != nil {
			b.ReportConfidence = makeMetricScore(cv.Cvss3xTemporal.ReportConfidence)
		}
	}

	// 环境指标
	if cv.Cvss3xEnvironmental != nil {
		if cv.Cvss3xEnvironmental.ConfidentialityRequirement != nil {
			b.ConfidentialityRequirement = makeMetricScore(cv.Cvss3xEnvironmental.ConfidentialityRequirement)
		}
		if cv.Cvss3xEnvironmental.IntegrityRequirement != nil {
			b.IntegrityRequirement = makeMetricScore(cv.Cvss3xEnvironmental.IntegrityRequirement)
		}
		if cv.Cvss3xEnvironmental.AvailabilityRequirement != nil {
			b.AvailabilityRequirement = makeMetricScore(cv.Cvss3xEnvironmental.AvailabilityRequirement)
		}

		modScopeChanged := c.isModifiedChangedScope()
		if cv.Cvss3xEnvironmental.ModifiedAttackVector != nil {
			b.ModifiedAttackVector = makeMetricScore(cv.Cvss3xEnvironmental.ModifiedAttackVector)
		}
		if cv.Cvss3xEnvironmental.ModifiedAttackComplexity != nil {
			b.ModifiedAttackComplexity = makeMetricScore(cv.Cvss3xEnvironmental.ModifiedAttackComplexity)
		}
		if cv.Cvss3xEnvironmental.ModifiedPrivilegesRequired != nil {
			b.ModifiedPrivilegesRequired = makeMetricScoreWithScore(cv.Cvss3xEnvironmental.ModifiedPrivilegesRequired,
				vector.GetPrivilegesRequiredScore(cv.Cvss3xEnvironmental.ModifiedPrivilegesRequired, modScopeChanged))
		}
		if cv.Cvss3xEnvironmental.ModifiedUserInteraction != nil {
			b.ModifiedUserInteraction = makeMetricScoreWithScore(cv.Cvss3xEnvironmental.ModifiedUserInteraction,
				vector.GetUserInteractionScore(cv.Cvss3xEnvironmental.ModifiedUserInteraction, cv.MinorVersion))
		}
		if cv.Cvss3xEnvironmental.ModifiedScope != nil {
			b.ModifiedScope = makeMetricScore(cv.Cvss3xEnvironmental.ModifiedScope)
		}
		if cv.Cvss3xEnvironmental.ModifiedConfidentiality != nil {
			b.ModifiedConfidentiality = makeMetricScore(cv.Cvss3xEnvironmental.ModifiedConfidentiality)
		}
		if cv.Cvss3xEnvironmental.ModifiedIntegrity != nil {
			b.ModifiedIntegrity = makeMetricScore(cv.Cvss3xEnvironmental.ModifiedIntegrity)
		}
		if cv.Cvss3xEnvironmental.ModifiedAvailability != nil {
			b.ModifiedAvailability = makeMetricScore(cv.Cvss3xEnvironmental.ModifiedAvailability)
		}
	}

	return b, nil
}

// AsMap 返回分数的 map 形式，便于动态序列化
func (s *AllScores) AsMap() map[string]float64 {
	if s == nil {
		return nil
	}
	m := map[string]float64{
		"baseScore":              s.BaseScore,
		"impactSubScore":         s.ImpactSubScore,
		"exploitabilitySubScore": s.ExploitabilitySubScore,
	}
	if s.HasTemporal {
		m["temporalScore"] = s.TemporalScore
	}
	if s.HasEnvironmental {
		m["environmentalScore"] = s.EnvironmentalScore
		m["modifiedImpactSubScore"] = s.ModifiedImpactSubScore
		m["modifiedExploitabilitySubScore"] = s.ModifiedExploitabilitySubScore
	}
	return m
}

// makeMetricScore 从 Vector 创建 MetricScore（使用 Vector 自身的 Score）
func makeMetricScore(v vector.Vector) MetricScore {
	if v == nil {
		return MetricScore{}
	}
	return MetricScore{
		ShortName: v.GetShortName(),
		LongName:  v.GetLongName(),
		Value:     string(v.GetShortValue()),
		Score:     v.GetScore(),
	}
}

// makeMetricScoreWithScore 从 Vector 创建 MetricScore，使用指定的分数
func makeMetricScoreWithScore(v vector.Vector, score float64) MetricScore {
	if v == nil {
		return MetricScore{}
	}
	return MetricScore{
		ShortName: v.GetShortName(),
		LongName:  v.GetLongName(),
		Value:     string(v.GetShortValue()),
		Score:     score,
	}
}
