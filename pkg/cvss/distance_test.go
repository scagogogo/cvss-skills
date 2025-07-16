package cvss

import (
	"testing"

	"github.com/scagogogo/cvss-parser/pkg/vector"
	"github.com/stretchr/testify/assert"
)

// TestNewDistanceCalculator 测试创建距离计算器
func TestNewDistanceCalculator(t *testing.T) {
	// 创建两个CVSS向量
	vector1 := createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High")
	vector2 := createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "Low")

	// 创建距离计算器
	dc := NewDistanceCalculator(vector1, vector2)

	// 断言
	assert.NotNil(t, dc)
	assert.Equal(t, vector1, dc.vector1)
	assert.Equal(t, vector2, dc.vector2)
}

// TestEuclideanDistance 测试欧几里得距离计算
func TestEuclideanDistance(t *testing.T) {
	testCases := []struct {
		name     string
		vector1  *Cvss3x
		vector2  *Cvss3x
		expected float64
	}{
		{
			name:     "Identical Vectors",
			vector1:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"),
			vector2:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"),
			expected: 0.0,
		},
		{
			name:     "One Difference - Availability",
			vector1:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"),
			vector2:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "Low"),
			expected: 0.34, // 欧几里得距离 = √((0.56-0.22)²) = 0.34
		},
		{
			name:     "Multiple Differences",
			vector1:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"),
			vector2:  createTestVector(3, 1, "Adjacent", "High", "Low", "Required", "Changed", "Low", "Low", "None"),
			expected: 1.56, // 多个差异的近似值
		},
		{
			name:     "One nil Base",
			vector1:  &Cvss3x{},
			vector2:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"),
			expected: 0.0,
		},
		{
			name: "With Temporal Metrics",
			vector1: createTestVectorWithTemporal(3, 1,
				"Network", "Low", "None", "None", "Unchanged", "High", "High", "High",
				"Functional", "Official Fix", "Confirmed"),
			vector2: createTestVectorWithTemporal(3, 1,
				"Network", "Low", "None", "None", "Unchanged", "High", "High", "High",
				"Proof of Concept", "Workaround", "Reasonable"),
			expected: 0.05, // 时间指标的差异比较小
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dc := NewDistanceCalculator(tc.vector1, tc.vector2)
			distance := dc.EuclideanDistance()
			assert.InDelta(t, tc.expected, distance, 0.05, "欧几里得距离计算错误")
		})
	}
}

// TestManhattanDistance 测试曼哈顿距离计算
func TestManhattanDistance(t *testing.T) {
	testCases := []struct {
		name     string
		vector1  *Cvss3x
		vector2  *Cvss3x
		expected float64
	}{
		{
			name:     "Identical Vectors",
			vector1:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"),
			vector2:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"),
			expected: 0.0,
		},
		{
			name:     "One Difference - Availability",
			vector1:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"),
			vector2:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "Low"),
			expected: 0.34, // 曼哈顿距离 = |0.56-0.22| = 0.34
		},
		{
			name:     "Multiple Differences",
			vector1:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"),
			vector2:  createTestVector(3, 1, "Adjacent", "High", "Low", "Required", "Changed", "Low", "Low", "None"),
			expected: 3.35, // 多个差异总和的近似值
		},
		{
			name:     "One nil Base",
			vector1:  &Cvss3x{},
			vector2:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"),
			expected: 0.0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dc := NewDistanceCalculator(tc.vector1, tc.vector2)
			distance := dc.ManhattanDistance()
			assert.InDelta(t, tc.expected, distance, 0.05, "曼哈顿距离计算错误")
		})
	}
}

// TestHammingDistance 测试汉明距离计算
func TestHammingDistance(t *testing.T) {
	testCases := []struct {
		name     string
		vector1  *Cvss3x
		vector2  *Cvss3x
		expected int
	}{
		{
			name:     "Identical Vectors",
			vector1:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"),
			vector2:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"),
			expected: 0,
		},
		{
			name:     "One Difference - Availability",
			vector1:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"),
			vector2:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "Low"),
			expected: 1,
		},
		{
			name:     "Multiple Differences",
			vector1:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"),
			vector2:  createTestVector(3, 1, "Adjacent", "High", "Low", "Required", "Changed", "Low", "Low", "None"),
			expected: 8,
		},
		{
			name:     "One nil Base",
			vector1:  &Cvss3x{},
			vector2:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"),
			expected: 0,
		},
		{
			name: "With Temporal Metrics - All Different",
			vector1: createTestVectorWithTemporal(3, 1,
				"Network", "Low", "None", "None", "Unchanged", "High", "High", "High",
				"Functional", "Official Fix", "Confirmed"),
			vector2: createTestVectorWithTemporal(3, 1,
				"Network", "Low", "None", "None", "Unchanged", "High", "High", "High",
				"Proof of Concept", "Workaround", "Reasonable"),
			expected: 3, // 3个时间指标都不同
		},
		{
			name: "With Temporal Metrics - Partially Different",
			vector1: createTestVectorWithTemporal(3, 1,
				"Network", "Low", "None", "None", "Unchanged", "High", "High", "High",
				"Functional", "Official Fix", "Confirmed"),
			vector2: createTestVectorWithTemporal(3, 1,
				"Network", "Low", "None", "None", "Unchanged", "High", "High", "High",
				"Functional", "Official Fix", "Reasonable"),
			expected: 1, // 只有ReportConfidence不同
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dc := NewDistanceCalculator(tc.vector1, tc.vector2)
			distance := dc.HammingDistance()
			assert.Equal(t, tc.expected, distance, "汉明距离计算错误")
		})
	}
}

// TestJaccardSimilarity 测试Jaccard相似度计算
func TestJaccardSimilarity(t *testing.T) {
	testCases := []struct {
		name     string
		vector1  *Cvss3x
		vector2  *Cvss3x
		expected float64
	}{
		{
			name:     "Identical Vectors",
			vector1:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"),
			vector2:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"),
			expected: 1.0, // 完全相同,相似度为1
		},
		{
			name:     "One Difference - Availability",
			vector1:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"),
			vector2:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "Low"),
			expected: 0.875, // 8个指标中有7个相同: 7/8 = 0.875
		},
		{
			name:     "Multiple Differences",
			vector1:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"),
			vector2:  createTestVector(3, 1, "Adjacent", "High", "Low", "Required", "Changed", "Low", "Low", "None"),
			expected: 0.0, // 8个指标全部不同: 0/8 = 0
		},
		{
			name:     "One nil Base",
			vector1:  &Cvss3x{},
			vector2:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"),
			expected: 0.0,
		},
		{
			name: "With Temporal Metrics - All Different",
			vector1: createTestVectorWithTemporal(3, 1,
				"Network", "Low", "None", "None", "Unchanged", "High", "High", "High",
				"Functional", "Official Fix", "Confirmed"),
			vector2: createTestVectorWithTemporal(3, 1,
				"Network", "Low", "None", "None", "Unchanged", "High", "High", "High",
				"Proof of Concept", "Workaround", "Reasonable"),
			expected: 0.727, // 11个指标中8个相同: 8/11 ≈ 0.727
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dc := NewDistanceCalculator(tc.vector1, tc.vector2)
			similarity := dc.JaccardSimilarity()
			assert.InDelta(t, tc.expected, similarity, 0.01, "Jaccard相似度计算错误")
		})
	}
}

// TestScoreDifference 测试评分差异计算
func TestScoreDifference(t *testing.T) {
	testCases := []struct {
		name     string
		vector1  *Cvss3x
		vector2  *Cvss3x
		expected float64
	}{
		{
			name:     "Identical Vectors",
			vector1:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"),
			vector2:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"),
			expected: 0.0,
		},
		{
			name:     "One Difference - Availability",
			vector1:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"),
			vector2:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "Low"),
			expected: 0.4, // 9.8 - 9.4 = 0.4
		},
		{
			name:     "Significant Difference",
			vector1:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"),
			vector2:  createTestVector(3, 1, "Physical", "High", "High", "Required", "Unchanged", "Low", "Low", "None"),
			expected: 7.1, // 9.8 - 2.7 = 7.1
		},
		{
			name:     "One nil Vector",
			vector1:  nil,
			vector2:  createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"),
			expected: 0.0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dc := NewDistanceCalculator(tc.vector1, tc.vector2)
			difference := dc.ScoreDifference()
			assert.InDelta(t, tc.expected, difference, 0.1, "评分差异计算错误")
		})
	}
}

// TestGetScoreDiff 测试获取分数差异
func TestGetScoreDiff(t *testing.T) {
	dc := NewDistanceCalculator(nil, nil) // 只是为了访问方法

	testCases := []struct {
		name     string
		v1       vector.Vector
		v2       vector.Vector
		expected float64
	}{
		{
			name:     "Both nil",
			v1:       nil,
			v2:       nil,
			expected: 0.0,
		},
		{
			name:     "First nil",
			v1:       nil,
			v2:       vector.AttackVectorNetwork,
			expected: 0.0,
		},
		{
			name:     "Second nil",
			v1:       vector.AttackVectorNetwork,
			v2:       nil,
			expected: 0.0,
		},
		{
			name:     "Same Vector",
			v1:       vector.AttackVectorNetwork,
			v2:       vector.AttackVectorNetwork,
			expected: 0.0,
		},
		{
			name:     "Different Vectors",
			v1:       vector.AttackVectorNetwork,  // 0.85
			v2:       vector.AttackVectorAdjacent, // 0.62
			expected: 0.23,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			diff := dc.getScoreDiff(tc.v1, tc.v2)
			assert.InDelta(t, tc.expected, diff, 0.01, "获取分数差异计算错误")
		})
	}
}

// 辅助函数：创建测试向量
func createTestVector(majorVersion, minorVersion int, av, ac, pr, ui, s, c, i, a string) *Cvss3x {
	cvss := NewCvss3x()
	cvss.MajorVersion = majorVersion
	cvss.MinorVersion = minorVersion

	cvss.Cvss3xBase = &Cvss3xBase{
		AttackVector:       getAttackVector(av),
		AttackComplexity:   getAttackComplexity(ac),
		PrivilegesRequired: getPrivilegesRequired(pr),
		UserInteraction:    getUserInteraction(ui),
		Scope:              getScope(s),
		Confidentiality:    getConfidentiality(c),
		Integrity:          getIntegrity(i),
		Availability:       getAvailability(a),
	}

	return cvss
}

// 辅助函数：创建带时间指标的测试向量
func createTestVectorWithTemporal(majorVersion, minorVersion int,
	av, ac, pr, ui, s, c, i, a string,
	e, rl, rc string) *Cvss3x {

	cvss := createTestVector(majorVersion, minorVersion, av, ac, pr, ui, s, c, i, a)

	cvss.Cvss3xTemporal = &Cvss3xTemporal{
		ExploitCodeMaturity: getExploitCodeMaturity(e),
		RemediationLevel:    getRemediationLevel(rl),
		ReportConfidence:    getReportConfidence(rc),
	}

	return cvss
}

// 下面是辅助函数，用于将字符串转换为Vector对象
func getAttackVector(v string) vector.Vector {
	switch v {
	case "Network":
		return vector.AttackVectorNetwork
	case "Adjacent":
		return vector.AttackVectorAdjacent
	case "Local":
		return vector.AttackVectorLocal
	case "Physical":
		return vector.AttackVectorPhysical
	default:
		return vector.AttackVectorNetwork
	}
}

func getAttackComplexity(v string) vector.Vector {
	if v == "High" {
		return vector.AttackComplexityHigh
	}
	return vector.AttackComplexityLow
}

func getPrivilegesRequired(v string) vector.Vector {
	switch v {
	case "High":
		return vector.PrivilegesRequiredHigh
	case "Low":
		return vector.PrivilegesRequiredLow
	default:
		return vector.PrivilegesRequiredNone
	}
}

func getUserInteraction(v string) vector.Vector {
	if v == "Required" {
		return vector.UserInteractionRequired
	}
	return vector.UserInteractionNone
}

func getScope(v string) vector.Vector {
	if v == "Changed" {
		return vector.ScopeChanged
	}
	return vector.ScopeUnchanged
}

func getConfidentiality(v string) vector.Vector {
	switch v {
	case "High":
		return vector.ConfidentialityHigh
	case "Low":
		return vector.ConfidentialityLow
	default:
		return vector.ConfidentialityNone
	}
}

func getIntegrity(v string) vector.Vector {
	switch v {
	case "High":
		return vector.IntegrityHigh
	case "Low":
		return vector.IntegrityLow
	default:
		return vector.IntegrityNone
	}
}

func getAvailability(v string) vector.Vector {
	switch v {
	case "High":
		return vector.AvailabilityHigh
	case "Low":
		return vector.AvailabilityLow
	default:
		return vector.AvailabilityNone
	}
}

func getExploitCodeMaturity(v string) vector.Vector {
	switch v {
	case "Unproven":
		return vector.ExploitCodeMaturityUnproven
	case "Proof of Concept":
		return vector.ExploitCodeMaturityProofOfConcept
	case "Functional":
		return vector.ExploitCodeMaturityFunctional
	case "High":
		return vector.ExploitCodeMaturityHigh
	default:
		return vector.ExploitCodeMaturityNotDefined
	}
}

func getRemediationLevel(v string) vector.Vector {
	switch v {
	case "Official Fix":
		return vector.RemediationLevelOfficialFix
	case "Temporary Fix":
		return vector.RemediationLevelTemporaryFix
	case "Workaround":
		return vector.RemediationLevelWorkaround
	case "Unavailable":
		return vector.RemediationLevelUnavailable
	default:
		return vector.RemediationLevelNotDefined
	}
}

func getReportConfidence(v string) vector.Vector {
	switch v {
	case "Unknown":
		return vector.ReportConfidenceUnknown
	case "Reasonable":
		return vector.ReportConfidenceReasonable
	case "Confirmed":
		return vector.ReportConfidenceConfirmed
	default:
		return vector.ReportConfidenceNotDefined
	}
}
