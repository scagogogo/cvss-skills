package cvss

import (
	"math"

	"github.com/scagogogo/cvss-parser/pkg/vector"
)

// DistanceCalculator 计算两个CVSS向量之间的距离
type DistanceCalculator struct {
	// 第一个向量
	vector1 *Cvss3x
	// 第二个向量
	vector2 *Cvss3x
}

// NewDistanceCalculator 创建一个新的距离计算器
func NewDistanceCalculator(vector1, vector2 *Cvss3x) *DistanceCalculator {
	return &DistanceCalculator{
		vector1: vector1,
		vector2: vector2,
	}
}

// isBaseMetricsComplete 检查两个向量的基础指标是否完整（所有必要指标非空）
func (dc *DistanceCalculator) isBaseMetricsComplete() bool {
	if dc.vector1 == nil || dc.vector2 == nil ||
		dc.vector1.Cvss3xBase == nil || dc.vector2.Cvss3xBase == nil {
		return false
	}

	b1 := dc.vector1.Cvss3xBase
	b2 := dc.vector2.Cvss3xBase

	return b1.AttackVector != nil && b2.AttackVector != nil &&
		b1.AttackComplexity != nil && b2.AttackComplexity != nil &&
		b1.PrivilegesRequired != nil && b2.PrivilegesRequired != nil &&
		b1.UserInteraction != nil && b2.UserInteraction != nil &&
		b1.Scope != nil && b2.Scope != nil &&
		b1.Confidentiality != nil && b2.Confidentiality != nil &&
		b1.Integrity != nil && b2.Integrity != nil &&
		b1.Availability != nil && b2.Availability != nil
}

// getBaseScoreDiffs 计算两个向量基础指标之间的分数差异
// 返回每个维度的分数差异（考虑了 PR 的 Scope 依赖）
func (dc *DistanceCalculator) getBaseScoreDiffs() []float64 {
	b1 := dc.vector1.Cvss3xBase
	b2 := dc.vector2.Cvss3xBase

	diffs := make([]float64, 0, 8)

	// AV
	diffs = append(diffs, math.Abs(b1.AttackVector.GetScore()-b2.AttackVector.GetScore()))

	// AC
	diffs = append(diffs, math.Abs(b1.AttackComplexity.GetScore()-b2.AttackComplexity.GetScore()))

	// PR — 需要 Scope 上下文才能得到正确分数
	pr1 := vector.GetPrivilegesRequiredScore(b1.PrivilegesRequired, vector.IsScopeChanged(b1.Scope))
	pr2 := vector.GetPrivilegesRequiredScore(b2.PrivilegesRequired, vector.IsScopeChanged(b2.Scope))
	diffs = append(diffs, math.Abs(pr1-pr2))

	// UI
	diffs = append(diffs, math.Abs(b1.UserInteraction.GetScore()-b2.UserInteraction.GetScore()))

	// Scope 特殊处理：转换为 0/1 数值
	scopeDiff := 0.0
	if b1.Scope.GetShortValue() != b2.Scope.GetShortValue() {
		scopeDiff = 1.0
	}
	diffs = append(diffs, scopeDiff)

	// C, I, A
	diffs = append(diffs, math.Abs(b1.Confidentiality.GetScore()-b2.Confidentiality.GetScore()))
	diffs = append(diffs, math.Abs(b1.Integrity.GetScore()-b2.Integrity.GetScore()))
	diffs = append(diffs, math.Abs(b1.Availability.GetScore()-b2.Availability.GetScore()))

	return diffs
}

// getTemporalScoreDiffs 计算两个向量时间指标之间的分数差异
// 如果任一向量缺少完整的时间指标，返回 nil
func (dc *DistanceCalculator) getTemporalScoreDiffs() []float64 {
	if dc.vector1.Cvss3xTemporal == nil || dc.vector2.Cvss3xTemporal == nil {
		return nil
	}

	t1 := dc.vector1.Cvss3xTemporal
	t2 := dc.vector2.Cvss3xTemporal

	// 检查所有时间指标是否都存在
	if t1.ExploitCodeMaturity == nil || t2.ExploitCodeMaturity == nil ||
		t1.RemediationLevel == nil || t2.RemediationLevel == nil ||
		t1.ReportConfidence == nil || t2.ReportConfidence == nil {
		return nil
	}

	diffs := make([]float64, 0, 3)
	diffs = append(diffs, math.Abs(t1.ExploitCodeMaturity.GetScore()-t2.ExploitCodeMaturity.GetScore()))
	diffs = append(diffs, math.Abs(t1.RemediationLevel.GetScore()-t2.RemediationLevel.GetScore()))
	diffs = append(diffs, math.Abs(t1.ReportConfidence.GetScore()-t2.ReportConfidence.GetScore()))

	return diffs
}

// EuclideanDistance 计算两个向量之间的欧几里得距离
// 使用各向量元素的分数作为维度值，计算n维空间中的直线距离
// PR 指标的分数会考虑 Scope 依赖
func (dc *DistanceCalculator) EuclideanDistance() float64 {
	if !dc.isBaseMetricsComplete() {
		return 0.0
	}

	sum := 0.0

	// 基础指标
	for _, diff := range dc.getBaseScoreDiffs() {
		sum += math.Pow(diff, 2)
	}

	// 时间指标
	temporalDiffs := dc.getTemporalScoreDiffs()
	if temporalDiffs != nil {
		for _, diff := range temporalDiffs {
			sum += math.Pow(diff, 2)
		}
	}

	if sum > 0 {
		return math.Sqrt(sum)
	}
	return 0.0
}

// ManhattanDistance 计算两个向量间的曼哈顿距离
// 使用各指标元素的分数差绝对值之和
// PR 指标的分数会考虑 Scope 依赖
func (dc *DistanceCalculator) ManhattanDistance() float64 {
	if !dc.isBaseMetricsComplete() {
		return 0.0
	}

	sum := 0.0

	// 基础指标
	for _, diff := range dc.getBaseScoreDiffs() {
		sum += diff
	}

	// 时间指标
	temporalDiffs := dc.getTemporalScoreDiffs()
	if temporalDiffs != nil {
		for _, diff := range temporalDiffs {
			sum += diff
		}
	}

	return sum
}

// HammingDistance 计算两个向量的汉明距离
// 计算有多少个指标不同
func (dc *DistanceCalculator) HammingDistance() int {
	diff := 0

	// 基础指标检查
	if dc.vector1.Cvss3xBase == nil || dc.vector2.Cvss3xBase == nil {
		return 0 // 如果任一向量没有基础指标，无法比较
	}

	// 检查各指标是否为空，并比较不同之处
	if dc.vector1.Cvss3xBase.AttackVector != nil && dc.vector2.Cvss3xBase.AttackVector != nil &&
		dc.vector1.Cvss3xBase.AttackVector.GetShortValue() != dc.vector2.Cvss3xBase.AttackVector.GetShortValue() {
		diff++
	}

	if dc.vector1.Cvss3xBase.AttackComplexity != nil && dc.vector2.Cvss3xBase.AttackComplexity != nil &&
		dc.vector1.Cvss3xBase.AttackComplexity.GetShortValue() != dc.vector2.Cvss3xBase.AttackComplexity.GetShortValue() {
		diff++
	}

	if dc.vector1.Cvss3xBase.PrivilegesRequired != nil && dc.vector2.Cvss3xBase.PrivilegesRequired != nil &&
		dc.vector1.Cvss3xBase.PrivilegesRequired.GetShortValue() != dc.vector2.Cvss3xBase.PrivilegesRequired.GetShortValue() {
		diff++
	}

	if dc.vector1.Cvss3xBase.UserInteraction != nil && dc.vector2.Cvss3xBase.UserInteraction != nil &&
		dc.vector1.Cvss3xBase.UserInteraction.GetShortValue() != dc.vector2.Cvss3xBase.UserInteraction.GetShortValue() {
		diff++
	}

	if dc.vector1.Cvss3xBase.Scope != nil && dc.vector2.Cvss3xBase.Scope != nil &&
		dc.vector1.Cvss3xBase.Scope.GetShortValue() != dc.vector2.Cvss3xBase.Scope.GetShortValue() {
		diff++
	}

	if dc.vector1.Cvss3xBase.Confidentiality != nil && dc.vector2.Cvss3xBase.Confidentiality != nil &&
		dc.vector1.Cvss3xBase.Confidentiality.GetShortValue() != dc.vector2.Cvss3xBase.Confidentiality.GetShortValue() {
		diff++
	}

	if dc.vector1.Cvss3xBase.Integrity != nil && dc.vector2.Cvss3xBase.Integrity != nil &&
		dc.vector1.Cvss3xBase.Integrity.GetShortValue() != dc.vector2.Cvss3xBase.Integrity.GetShortValue() {
		diff++
	}

	if dc.vector1.Cvss3xBase.Availability != nil && dc.vector2.Cvss3xBase.Availability != nil &&
		dc.vector1.Cvss3xBase.Availability.GetShortValue() != dc.vector2.Cvss3xBase.Availability.GetShortValue() {
		diff++
	}

	// 时间指标 (如果都存在)
	if dc.vector1.Cvss3xTemporal != nil && dc.vector2.Cvss3xTemporal != nil {
		// 利用代码成熟度
		if dc.vector1.Cvss3xTemporal.ExploitCodeMaturity != nil && dc.vector2.Cvss3xTemporal.ExploitCodeMaturity != nil &&
			dc.vector1.Cvss3xTemporal.ExploitCodeMaturity.GetShortValue() != dc.vector2.Cvss3xTemporal.ExploitCodeMaturity.GetShortValue() {
			diff++
		}

		// 修复级别
		if dc.vector1.Cvss3xTemporal.RemediationLevel != nil && dc.vector2.Cvss3xTemporal.RemediationLevel != nil &&
			dc.vector1.Cvss3xTemporal.RemediationLevel.GetShortValue() != dc.vector2.Cvss3xTemporal.RemediationLevel.GetShortValue() {
			diff++
		}

		// 报告置信度
		if dc.vector1.Cvss3xTemporal.ReportConfidence != nil && dc.vector2.Cvss3xTemporal.ReportConfidence != nil &&
			dc.vector1.Cvss3xTemporal.ReportConfidence.GetShortValue() != dc.vector2.Cvss3xTemporal.ReportConfidence.GetShortValue() {
			diff++
		}
	}

	return diff
}

// JaccardSimilarity 计算两个向量的Jaccard相似度
// 相同元素数量除以总元素数量
func (dc *DistanceCalculator) JaccardSimilarity() float64 {
	// 检查向量或基础指标是否为空
	if dc.vector1 == nil || dc.vector2 == nil ||
		dc.vector1.Cvss3xBase == nil || dc.vector2.Cvss3xBase == nil {
		return 0.0
	}

	// 计算总指标数和不同指标数
	hammingDist := dc.HammingDistance()

	// 计算总指标数
	totalMetrics := 8 // 基础指标数量
	if dc.vector1.Cvss3xTemporal != nil && dc.vector2.Cvss3xTemporal != nil &&
		dc.vector1.Cvss3xTemporal.ExploitCodeMaturity != nil && dc.vector2.Cvss3xTemporal.ExploitCodeMaturity != nil &&
		dc.vector1.Cvss3xTemporal.RemediationLevel != nil && dc.vector2.Cvss3xTemporal.RemediationLevel != nil &&
		dc.vector1.Cvss3xTemporal.ReportConfidence != nil && dc.vector2.Cvss3xTemporal.ReportConfidence != nil {
		totalMetrics += 3 // 完整的时间指标
	}

	// 相同指标数量
	sameMetrics := totalMetrics - hammingDist

	// Jaccard相似度 = 相同元素数量 / 总元素数量
	return float64(sameMetrics) / float64(totalMetrics)
}

// ScoreDifference 计算两个向量的CVSS分数差异
func (dc *DistanceCalculator) ScoreDifference() float64 {
	if dc.vector1 == nil || dc.vector2 == nil {
		return 0.0
	}

	calc1 := NewCalculator(dc.vector1)
	calc2 := NewCalculator(dc.vector2)

	score1, err1 := calc1.Calculate()
	score2, err2 := calc2.Calculate()

	// 如果任一计算出错，返回0
	if err1 != nil || err2 != nil {
		return 0.0
	}

	return math.Abs(score1 - score2)
}

// 获取两个向量元素的分数差异
func (dc *DistanceCalculator) getScoreDiff(v1, v2 vector.Vector) float64 {
	if v1 == nil || v2 == nil {
		return 0
	}
	return v1.GetScore() - v2.GetScore()
}
