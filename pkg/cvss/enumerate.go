package cvss

import (
	"fmt"

	"github.com/scagogogo/cvss-parser/pkg/vector"
)

// MetricInfo 表示一个指标的完整信息（所有可选值）
type MetricInfo struct {
	ShortName string          // 短名称，如 "AV"
	LongName  string          // 长名称，如 "Attack Vector"
	Group     string          // 所属组：Base/Temporal/Environmental
	Values    []MetricValueInfo // 所有可选值
}

// MetricValueInfo 表示一个指标值的完整信息
type MetricValueInfo struct {
	ShortValue rune    // 短值，如 'N'
	LongValue  string  // 长值，如 "Network"
	Score      float64 // 分数（注意：PR/UI 的分数依赖上下文）
	IsNotDefined bool  // 是否为 "Not Defined" 值
}

// String 返回指标信息的可读表示
func (mi MetricInfo) String() string {
	s := fmt.Sprintf("%s (%s) [%s]:\n", mi.ShortName, mi.LongName, mi.Group)
	for _, v := range mi.Values {
		s += fmt.Sprintf("  %c = %s (score: %.2f)\n", v.ShortValue, v.LongValue, v.Score)
	}
	return s
}

// ListAllMetrics 列出所有指标及其可选值
// 返回按 Base/Temporal/Environmental 分组的完整信息
//
// 用法:
//
//	metrics := cvss.ListAllMetrics()
//	for _, m := range metrics {
//	    fmt.Println(m.String())
//	}
func ListAllMetrics() []MetricInfo {
	var metrics []MetricInfo

	// Base metrics
	metrics = append(metrics,
		buildMetricInfo("AV", "Attack Vector", "Base",
			[]rune{'N', 'A', 'L', 'P'},
			[]string{"Network", "Adjacent", "Local", "Physical"},
			[]float64{0.85, 0.62, 0.55, 0.20},
		),
		buildMetricInfo("AC", "Attack Complexity", "Base",
			[]rune{'L', 'H'},
			[]string{"Low", "High"},
			[]float64{0.77, 0.44},
		),
		buildMetricInfo("PR", "Privileges Required", "Base",
			[]rune{'N', 'L', 'H'},
			[]string{"None", "Low", "High"},
			[]float64{0.85, 0.62, 0.27}, // Scope Unchanged 默认值
		),
		buildMetricInfo("UI", "User Interaction", "Base",
			[]rune{'N', 'R'},
			[]string{"None", "Required"},
			[]float64{0.85, 0.62}, // v3.1 默认值
		),
		buildMetricInfo("S", "Scope", "Base",
			[]rune{'U', 'C'},
			[]string{"Unchanged", "Changed"},
			[]float64{0, 0}, // Scope 无分数
		),
		buildMetricInfo("C", "Confidentiality", "Base",
			[]rune{'H', 'L', 'N'},
			[]string{"High", "Low", "None"},
			[]float64{0.56, 0.22, 0},
		),
		buildMetricInfo("I", "Integrity", "Base",
			[]rune{'H', 'L', 'N'},
			[]string{"High", "Low", "None"},
			[]float64{0.56, 0.22, 0},
		),
		buildMetricInfo("A", "Availability", "Base",
			[]rune{'H', 'L', 'N'},
			[]string{"High", "Low", "None"},
			[]float64{0.56, 0.22, 0},
		),
	)

	// Temporal metrics
	metrics = append(metrics,
		buildMetricInfo("E", "Exploit Code Maturity", "Temporal",
			[]rune{'X', 'H', 'F', 'P', 'U'},
			[]string{"Not Defined", "High", "Functional", "Proof-of-Concept", "Unproven"},
			[]float64{1.0, 1.0, 0.97, 0.94, 0.91},
		),
		buildMetricInfo("RL", "Remediation Level", "Temporal",
			[]rune{'X', 'O', 'T', 'W', 'U'},
			[]string{"Not Defined", "Official Fix", "Temporary Fix", "Workaround", "Unavailable"},
			[]float64{1.0, 0.95, 0.96, 0.97, 1.0},
		),
		buildMetricInfo("RC", "Report Confidence", "Temporal",
			[]rune{'X', 'C', 'R', 'U'},
			[]string{"Not Defined", "Confirmed", "Reasonable", "Unknown"},
			[]float64{1.0, 1.0, 0.96, 0.92},
		),
	)

	// Environmental metrics — requirements
	metrics = append(metrics,
		buildMetricInfo("CR", "Confidentiality Requirement", "Environmental",
			[]rune{'X', 'H', 'M', 'L'},
			[]string{"Not Defined", "High", "Medium", "Low"},
			[]float64{1.0, 1.5, 1.0, 0.5},
		),
		buildMetricInfo("IR", "Integrity Requirement", "Environmental",
			[]rune{'X', 'H', 'M', 'L'},
			[]string{"Not Defined", "High", "Medium", "Low"},
			[]float64{1.0, 1.5, 1.0, 0.5},
		),
		buildMetricInfo("AR", "Availability Requirement", "Environmental",
			[]rune{'X', 'H', 'M', 'L'},
			[]string{"Not Defined", "High", "Medium", "Low"},
			[]float64{1.0, 1.5, 1.0, 0.5},
		),
	)

	// Environmental metrics — modified
	modifiedMetrics := []struct {
		shortName string
		longName  string
		shortVals []rune
		longVals  []string
		scores    []float64
	}{
		{"MAV", "Modified Attack Vector", []rune{'X', 'N', 'A', 'L', 'P'},
			[]string{"Not Defined", "Network", "Adjacent", "Local", "Physical"},
			[]float64{1.0, 0.85, 0.62, 0.55, 0.20}},
		{"MAC", "Modified Attack Complexity", []rune{'X', 'L', 'H'},
			[]string{"Not Defined", "Low", "High"},
			[]float64{1.0, 0.77, 0.44}},
		{"MPR", "Modified Privileges Required", []rune{'X', 'N', 'L', 'H'},
			[]string{"Not Defined", "None", "Low", "High"},
			[]float64{1.0, 0.85, 0.62, 0.27}},
		{"MUI", "Modified User Interaction", []rune{'X', 'N', 'R'},
			[]string{"Not Defined", "None", "Required"},
			[]float64{1.0, 0.85, 0.62}},
		{"MS", "Modified Scope", []rune{'X', 'U', 'C'},
			[]string{"Not Defined", "Unchanged", "Changed"},
			[]float64{1.0, 0, 0}},
		{"MC", "Modified Confidentiality", []rune{'X', 'H', 'L', 'N'},
			[]string{"Not Defined", "High", "Low", "None"},
			[]float64{1.0, 0.56, 0.22, 0}},
		{"MI", "Modified Integrity", []rune{'X', 'H', 'L', 'N'},
			[]string{"Not Defined", "High", "Low", "None"},
			[]float64{1.0, 0.56, 0.22, 0}},
		{"MA", "Modified Availability", []rune{'X', 'H', 'L', 'N'},
			[]string{"Not Defined", "High", "Low", "None"},
			[]float64{1.0, 0.56, 0.22, 0}},
	}

	for _, m := range modifiedMetrics {
		metrics = append(metrics, buildMetricInfo(m.shortName, m.longName, "Environmental",
			m.shortVals, m.longVals, m.scores))
	}

	return metrics
}

// buildMetricInfo 构建 MetricInfo
func buildMetricInfo(shortName, longName, group string, shortVals []rune, longVals []string, scores []float64) MetricInfo {
	mi := MetricInfo{
		ShortName: shortName,
		LongName:  longName,
		Group:     group,
	}
	for i, sv := range shortVals {
		mi.Values = append(mi.Values, MetricValueInfo{
			ShortValue:  sv,
			LongValue:   longVals[i],
			Score:       scores[i],
			IsNotDefined: sv == 'X',
		})
	}
	return mi
}

// GetMetricInfo 获取指定指标的信息
func GetMetricInfo(shortName string) (MetricInfo, error) {
	for _, m := range ListAllMetrics() {
		if m.ShortName == shortName {
			return m, nil
		}
	}
	return MetricInfo{}, fmt.Errorf("unknown metric: %s", shortName)
}

// GetValidValues 获取指定指标的所有合法值
// 返回短值切片（如 ['N', 'A', 'L', 'P']）和对应的长值切片
func GetValidValues(shortName string) ([]rune, []string, error) {
	info, err := GetMetricInfo(shortName)
	if err != nil {
		return nil, nil, err
	}
	shortVals := make([]rune, len(info.Values))
	longVals := make([]string, len(info.Values))
	for i, v := range info.Values {
		shortVals[i] = v.ShortValue
		longVals[i] = v.LongValue
	}
	return shortVals, longVals, nil
}

// IsValidMetricValue 检查指标值是否合法
func IsValidMetricValue(shortName string, value rune) bool {
	shortVals, _, err := GetValidValues(shortName)
	if err != nil {
		return false
	}
	for _, v := range shortVals {
		if v == value {
			return true
		}
	}
	return false
}

// VectorIterator 遍历所有可能的 CVSS 向量组合
// 只遍历基础指标（8个），共 4×2×3×2×2×3×3×3 = 2592 种组合
type VectorIterator struct {
	metricValues map[string][]rune
	metricOrder  []string
	current      map[string]int // 每个指标的当前索引
	done         bool
	version      int // minor version (0 or 1)
}

// NewVectorIterator 创建一个新的向量迭代器
// minorVersion 指定版本号（0 或 1）
func NewVectorIterator(minorVersion int) *VectorIterator {
	metricValues := map[string][]rune{
		"AV": {'N', 'A', 'L', 'P'},
		"AC": {'L', 'H'},
		"PR": {'N', 'L', 'H'},
		"UI": {'N', 'R'},
		"S":  {'U', 'C'},
		"C":  {'H', 'L', 'N'},
		"I":  {'H', 'L', 'N'},
		"A":  {'H', 'L', 'N'},
	}
	metricOrder := []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}

	current := make(map[string]int)
	for _, m := range metricOrder {
		current[m] = 0
	}

	return &VectorIterator{
		metricValues: metricValues,
		metricOrder:  metricOrder,
		current:      current,
		done:         false,
		version:      minorVersion,
	}
}

// Next 返回下一个向量，如果没有更多组合则返回 nil
func (vi *VectorIterator) Next() *Cvss3x {
	if vi.done {
		return nil
	}

	// 构建当前向量
	cv, _ := NewCvss3xWithOptions(WithVersion(3, vi.version))
	for _, m := range vi.metricOrder {
		idx := vi.current[m]
		val := vi.metricValues[m][idx]
		switch m {
		case "AV":
			cv.Cvss3xBase.AttackVector, _ = vector.GetAttackVector(val)
		case "AC":
			cv.Cvss3xBase.AttackComplexity, _ = vector.GetAttackComplexity(val)
		case "PR":
			cv.Cvss3xBase.PrivilegesRequired, _ = vector.GetPrivilegesRequired(val)
		case "UI":
			cv.Cvss3xBase.UserInteraction, _ = vector.GetUserInteraction(val)
		case "S":
			cv.Cvss3xBase.Scope, _ = vector.GetScope(val)
		case "C":
			cv.Cvss3xBase.Confidentiality, _ = vector.GetConfidentiality(val)
		case "I":
			cv.Cvss3xBase.Integrity, _ = vector.GetIntegrity(val)
		case "A":
			cv.Cvss3xBase.Availability, _ = vector.GetAvailability(val)
		}
	}

	// 推进索引（类似进位计数器）
	vi.advance()

	return cv
}

// advance 推进迭代器到下一个组合
func (vi *VectorIterator) advance() {
	for i := len(vi.metricOrder) - 1; i >= 0; i-- {
		m := vi.metricOrder[i]
		vi.current[m]++
		if vi.current[m] < len(vi.metricValues[m]) {
			return
		}
		// 进位
		vi.current[m] = 0
	}
	// 所有指标都已回绕到0，迭代完成
	vi.done = true
}

// Reset 重置迭代器到初始位置
func (vi *VectorIterator) Reset() {
	for _, m := range vi.metricOrder {
		vi.current[m] = 0
	}
	vi.done = false
}

// TotalCombinations 返回总组合数
func (vi *VectorIterator) TotalCombinations() int {
	total := 1
	for _, m := range vi.metricOrder {
		total *= len(vi.metricValues[m])
	}
	return total
}
