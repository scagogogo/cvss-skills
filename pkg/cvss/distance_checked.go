package cvss

import (
	"fmt"
	"math"
)

// errIncompleteMetrics 表示基础指标不完整，无法计算距离
var errIncompleteMetrics = fmt.Errorf("base metrics incomplete, cannot compute distance")

// EuclideanDistanceChecked 计算两个向量之间的欧几里得距离，返回 error 而非静默 0.0
// 当基础指标不完整时返回错误，而非静默返回 0.0
func (dc *DistanceCalculator) EuclideanDistanceChecked() (float64, error) {
	if !dc.isBaseMetricsComplete() {
		return 0, errIncompleteMetrics
	}

	sum := 0.0
	for _, diff := range dc.getBaseScoreDiffs() {
		sum += math.Pow(diff, 2)
	}

	temporalDiffs := dc.getTemporalScoreDiffs()
	if temporalDiffs != nil {
		for _, diff := range temporalDiffs {
			sum += math.Pow(diff, 2)
		}
	}

	if sum > 0 {
		return math.Sqrt(sum), nil
	}
	return 0.0, nil
}

// ManhattanDistanceChecked 计算两个向量间的曼哈顿距离，返回 error 而非静默 0.0
func (dc *DistanceCalculator) ManhattanDistanceChecked() (float64, error) {
	if !dc.isBaseMetricsComplete() {
		return 0, errIncompleteMetrics
	}

	sum := 0.0
	for _, diff := range dc.getBaseScoreDiffs() {
		sum += diff
	}

	temporalDiffs := dc.getTemporalScoreDiffs()
	if temporalDiffs != nil {
		for _, diff := range temporalDiffs {
			sum += diff
		}
	}

	return sum, nil
}

// ScoreDifferenceChecked 计算两个向量的CVSS分数差异，返回 error 而非静默 0.0
func (dc *DistanceCalculator) ScoreDifferenceChecked() (float64, error) {
	if dc.vector1 == nil || dc.vector2 == nil {
		return 0, fmt.Errorf("one or both vectors are nil")
	}

	calc1 := NewCalculator(dc.vector1)
	calc2 := NewCalculator(dc.vector2)

	score1, err1 := calc1.Calculate()
	score2, err2 := calc2.Calculate()

	if err1 != nil {
		return 0, fmt.Errorf("failed to calculate score for vector1: %w", err1)
	}
	if err2 != nil {
		return 0, fmt.Errorf("failed to calculate score for vector2: %w", err2)
	}

	return math.Abs(score1 - score2), nil
}

// EuclideanDistanceWithEnvChecked 计算包含环境指标的欧几里得距离，返回 error
func (dc *DistanceCalculator) EuclideanDistanceWithEnvChecked() (float64, error) {
	if !dc.isBaseMetricsComplete() {
		return 0, errIncompleteMetrics
	}

	sum := 0.0
	for _, diff := range dc.getBaseScoreDiffs() {
		sum += math.Pow(diff, 2)
	}

	temporalDiffs := dc.getTemporalScoreDiffs()
	if temporalDiffs != nil {
		for _, diff := range temporalDiffs {
			sum += math.Pow(diff, 2)
		}
	}

	if dc.isEnvironmentalMetricsComplete() {
		for _, diff := range dc.getEnvironmentalScoreDiffs() {
			sum += math.Pow(diff, 2)
		}
	}

	if sum > 0 {
		return math.Sqrt(sum), nil
	}
	return 0.0, nil
}

// ManhattanDistanceWithEnvChecked 计算包含环境指标的曼哈顿距离，返回 error
func (dc *DistanceCalculator) ManhattanDistanceWithEnvChecked() (float64, error) {
	if !dc.isBaseMetricsComplete() {
		return 0, errIncompleteMetrics
	}

	sum := 0.0
	for _, diff := range dc.getBaseScoreDiffs() {
		sum += diff
	}

	temporalDiffs := dc.getTemporalScoreDiffs()
	if temporalDiffs != nil {
		for _, diff := range temporalDiffs {
			sum += diff
		}
	}

	if dc.isEnvironmentalMetricsComplete() {
		for _, diff := range dc.getEnvironmentalScoreDiffs() {
			sum += diff
		}
	}

	return sum, nil
}
