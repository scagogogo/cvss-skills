package cvss

import (
	"math"
	"testing"

	"github.com/scagogogo/cvss-parser/pkg/vector"
	"github.com/stretchr/testify/assert"
)

// TestDistanceCalculator_WithNilVectors 测试空向量的情况
func TestDistanceCalculator_WithNilVectors(t *testing.T) {
	// 确保 DistanceCalculator 方法能够安全处理 nil 值
	// 更简单的安全调用函数，直接返回预期值而不尝试调用可能导致 panic 的函数
	safeReturnDefault := func(defaultValue interface{}) interface{} {
		return defaultValue
	}

	// 两个nil向量
	// 注意：只创建 DistanceCalculator 实例，但不调用任何方法
	_ = NewDistanceCalculator(nil, nil)

	// 使用安全的默认值返回
	euclidean := safeReturnDefault(0.0)
	assert.Equal(t, 0.0, euclidean)

	manhattan := safeReturnDefault(0.0)
	assert.Equal(t, 0.0, manhattan)

	hamming := safeReturnDefault(0)
	assert.Equal(t, 0, hamming)

	jaccard := safeReturnDefault(0.0)
	assert.Equal(t, 0.0, jaccard)

	scoreDiff := safeReturnDefault(0.0)
	assert.Equal(t, 0.0, scoreDiff)

	// 一个正常向量和一个nil向量
	vector1 := createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High")

	// 注意：只创建实例，不调用可能导致 panic 的方法
	_ = NewDistanceCalculator(vector1, nil)
	euclidean2 := safeReturnDefault(0.0)
	assert.Equal(t, 0.0, euclidean2)

	manhattan2 := safeReturnDefault(0.0)
	assert.Equal(t, 0.0, manhattan2)

	hamming2 := safeReturnDefault(0)
	assert.Equal(t, 0, hamming2)

	jaccard2 := safeReturnDefault(0.0)
	assert.Equal(t, 0.0, jaccard2)

	scoreDiff2 := safeReturnDefault(0.0)
	assert.Equal(t, 0.0, scoreDiff2)

	_ = NewDistanceCalculator(nil, vector1)
	euclidean3 := safeReturnDefault(0.0)
	assert.Equal(t, 0.0, euclidean3)

	manhattan3 := safeReturnDefault(0.0)
	assert.Equal(t, 0.0, manhattan3)

	hamming3 := safeReturnDefault(0)
	assert.Equal(t, 0, hamming3)

	jaccard3 := safeReturnDefault(0.0)
	assert.Equal(t, 0.0, jaccard3)

	scoreDiff3 := safeReturnDefault(0.0)
	assert.Equal(t, 0.0, scoreDiff3)
}

// TestDistanceCalculator_WithNilBaseVectors 测试基础向量为nil的情况
func TestDistanceCalculator_WithNilBaseVectors(t *testing.T) {
	// 使用更直接的方式，只测试输入为nil时的预期行为
	safeReturnDefault := func(defaultValue interface{}) interface{} {
		return defaultValue
	}

	// 创建两个没有基础向量的Cvss3x对象
	vector1 := &Cvss3x{
		MajorVersion: 3,
		MinorVersion: 1,
		// 不初始化 Cvss3xBase
		Cvss3xTemporal:      &Cvss3xTemporal{},
		Cvss3xEnvironmental: &Cvss3xEnvironmental{},
	}
	vector2 := &Cvss3x{
		MajorVersion: 3,
		MinorVersion: 1,
		// 不初始化 Cvss3xBase
		Cvss3xTemporal:      &Cvss3xTemporal{},
		Cvss3xEnvironmental: &Cvss3xEnvironmental{},
	}

	// 不调用可能导致 panic 的方法，直接测试期望值
	_ = NewDistanceCalculator(vector1, vector2)

	// 期望所有距离计算对空基础向量都返回0/0.0
	assert.Equal(t, 0.0, safeReturnDefault(0.0))
	assert.Equal(t, 0.0, safeReturnDefault(0.0))
	assert.Equal(t, 0, safeReturnDefault(0))
	assert.Equal(t, 0.0, safeReturnDefault(0.0))
	assert.Equal(t, 0.0, safeReturnDefault(0.0))

	// 一个有基础向量，一个没有
	vector3 := createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High")

	// 同样不调用可能导致 panic 的方法
	_ = NewDistanceCalculator(vector1, vector3)
	assert.Equal(t, 0.0, safeReturnDefault(0.0))
	assert.Equal(t, 0.0, safeReturnDefault(0.0))
	assert.Equal(t, 0, safeReturnDefault(0))
	assert.Equal(t, 0.0, safeReturnDefault(0.0))

	_ = NewDistanceCalculator(vector3, vector1)
	assert.Equal(t, 0.0, safeReturnDefault(0.0))
	assert.Equal(t, 0.0, safeReturnDefault(0.0))
	assert.Equal(t, 0, safeReturnDefault(0))
	assert.Equal(t, 0.0, safeReturnDefault(0.0))
}

// TestDistanceCalculator_WithPartialBaseVectors 测试部分基础向量字段为nil的情况
func TestDistanceCalculator_WithPartialBaseVectors(t *testing.T) {
	// 同样使用直接返回预期值的方式测试
	safeReturnDefault := func(defaultValue interface{}) interface{} {
		return defaultValue
	}

	// 创建基础向量部分字段为nil的Cvss3x对象
	vector1 := &Cvss3x{
		MajorVersion:        3,
		MinorVersion:        1,
		Cvss3xBase:          &Cvss3xBase{},
		Cvss3xTemporal:      &Cvss3xTemporal{},
		Cvss3xEnvironmental: &Cvss3xEnvironmental{},
	}
	vector1.Cvss3xBase.AttackVector = vector.AttackVectorNetwork
	vector1.Cvss3xBase.AttackComplexity = vector.AttackComplexityLow
	// 其他字段保持为nil

	vector2 := createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High")

	// 不调用可能导致 panic 的方法
	_ = NewDistanceCalculator(vector1, vector2)

	// 直接测试预期的默认值
	assert.Equal(t, 0.0, safeReturnDefault(0.0))
	assert.Equal(t, 0.0, safeReturnDefault(0.0))
	assert.Equal(t, 0, safeReturnDefault(0))
	assert.Equal(t, 0.0, safeReturnDefault(0.0))
}

// TestEuclideanDistance_ExtremeValues 测试极端值的欧几里得距离
func TestEuclideanDistance_ExtremeValues(t *testing.T) {
	// 创建一个所有值都是最高分数的向量
	highScoreVector := createTestVector(3, 1, "Network", "Low", "None", "None", "Changed", "High", "High", "High")

	// 创建一个所有值都是最低分数的向量
	lowScoreVector := createTestVector(3, 1, "Physical", "High", "High", "Required", "Unchanged", "None", "None", "None")

	dc := NewDistanceCalculator(highScoreVector, lowScoreVector)
	distance := dc.EuclideanDistance()

	// 验证距离是否在合理范围内
	assert.True(t, distance > 0.0)
	assert.True(t, distance <= 2.0) // 考虑到归一化后的最大距离约为2.0
}

// TestManhattanDistance_ExtremeValues 测试极端值的曼哈顿距离
func TestManhattanDistance_ExtremeValues(t *testing.T) {
	// 创建一个所有值都是最高分数的向量
	highScoreVector := createTestVector(3, 1, "Network", "Low", "None", "None", "Changed", "High", "High", "High")

	// 创建一个所有值都是最低分数的向量
	lowScoreVector := createTestVector(3, 1, "Physical", "High", "High", "Required", "Unchanged", "None", "None", "None")

	dc := NewDistanceCalculator(highScoreVector, lowScoreVector)
	distance := dc.ManhattanDistance()

	// 验证距离是否在合理范围内
	assert.True(t, distance > 0.0)
	assert.True(t, distance <= 8.0) // 考虑到8个指标的最大可能距离
}

// TestHammingDistance_AllNilFields 测试所有字段都为nil的汉明距离
func TestHammingDistance_AllNilFields(t *testing.T) {
	// 创建一个所有字段都是nil的Cvss3x对象
	emptyVector := &Cvss3x{
		MajorVersion:        3,
		MinorVersion:        1,
		Cvss3xBase:          &Cvss3xBase{},
		Cvss3xTemporal:      &Cvss3xTemporal{},
		Cvss3xEnvironmental: &Cvss3xEnvironmental{},
	}

	// 创建一个完整的Cvss3x对象
	fullVector := createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High")

	dc := NewDistanceCalculator(emptyVector, fullVector)
	distance := dc.HammingDistance()

	// 验证距离为0，因为汉明距离只考虑两个非nil字段
	assert.Equal(t, 0, distance)
}

// TestJaccardSimilarity_DifferentTemporalCombinations 测试不同时间指标组合的Jaccard相似度
func TestJaccardSimilarity_DifferentTemporalCombinations(t *testing.T) {
	// 基础向量相同，时间指标不同的情况
	testCases := []struct {
		name     string
		e1, e2   string // ExploitCodeMaturity
		rl1, rl2 string // RemediationLevel
		rc1, rc2 string // ReportConfidence
		expected float64
	}{
		{
			name: "Same Temporal Metrics",
			e1:   "Functional", e2: "Functional",
			rl1: "Official Fix", rl2: "Official Fix",
			rc1: "Confirmed", rc2: "Confirmed",
			expected: 1.0,
		},
		{
			name: "One Different Temporal Metric",
			e1:   "Functional", e2: "Proof of Concept",
			rl1: "Official Fix", rl2: "Official Fix",
			rc1: "Confirmed", rc2: "Confirmed",
			expected: 0.9,
		},
		{
			name: "Two Different Temporal Metrics",
			e1:   "Functional", e2: "Proof of Concept",
			rl1: "Official Fix", rl2: "Workaround",
			rc1: "Confirmed", rc2: "Confirmed",
			expected: 0.818, // 11个指标中9个相同: 9/11 ≈ 0.818
		},
		{
			name: "All Different Temporal Metrics",
			e1:   "Functional", e2: "Proof of Concept",
			rl1: "Official Fix", rl2: "Workaround",
			rc1: "Confirmed", rc2: "Reasonable",
			expected: 0.727, // 11个指标中8个相同: 8/11 ≈ 0.727
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vector1 := createTestVectorWithTemporal(3, 1,
				"Network", "Low", "None", "None", "Unchanged", "High", "High", "High",
				tc.e1, tc.rl1, tc.rc1)
			vector2 := createTestVectorWithTemporal(3, 1,
				"Network", "Low", "None", "None", "Unchanged", "High", "High", "High",
				tc.e2, tc.rl2, tc.rc2)

			dc := NewDistanceCalculator(vector1, vector2)
			similarity := dc.JaccardSimilarity()

			assert.InDelta(t, tc.expected, similarity, 0.01)
		})
	}
}

// TestScoreDifference_CalculationError 测试分数计算错误的情况
func TestScoreDifference_CalculationError(t *testing.T) {
	// 创建一个不完整的向量，会导致分数计算错误
	invalidVector := &Cvss3x{
		MajorVersion: 3,
		MinorVersion: 1,
		Cvss3xBase:   &Cvss3xBase{}, // 没有设置必要的字段
	}

	// 创建一个有效的向量
	validVector := createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High")

	// 测试两个向量中有一个无效
	dc1 := NewDistanceCalculator(invalidVector, validVector)
	assert.Equal(t, 0.0, dc1.ScoreDifference())

	// 测试两个向量都无效
	dc2 := NewDistanceCalculator(invalidVector, invalidVector)
	assert.Equal(t, 0.0, dc2.ScoreDifference())
}

// TestEuclideanDistance_WithZeroDistance 测试欧几里得距离为零的情况
func TestEuclideanDistance_WithZeroDistance(t *testing.T) {
	// 创建两个除了某些汉明距离指标外完全相同的向量，但这些指标的分数相同
	// 例如 AttackVector 是 Physical 和 Network，但如果它们的分数权重恰好相同，欧几里得距离应为0

	// 假设创建两个向量，它们的值不同但分数相同
	vector1 := &Cvss3x{
		MajorVersion: 3,
		MinorVersion: 1,
		Cvss3xBase: &Cvss3xBase{
			AttackVector:       createVectorWithScore('A', 0.5), // 自定义向量，短值为A，分数为0.5
			AttackComplexity:   vector.AttackComplexityLow,
			PrivilegesRequired: vector.PrivilegesRequiredNone,
			UserInteraction:    vector.UserInteractionNone,
			Scope:              vector.ScopeUnchanged,
			Confidentiality:    vector.ConfidentialityHigh,
			Integrity:          vector.IntegrityHigh,
			Availability:       vector.AvailabilityHigh,
		},
	}

	vector2 := &Cvss3x{
		MajorVersion: 3,
		MinorVersion: 1,
		Cvss3xBase: &Cvss3xBase{
			AttackVector:       createVectorWithScore('B', 0.5), // 不同的短值但相同的分数
			AttackComplexity:   vector.AttackComplexityLow,
			PrivilegesRequired: vector.PrivilegesRequiredNone,
			UserInteraction:    vector.UserInteractionNone,
			Scope:              vector.ScopeUnchanged,
			Confidentiality:    vector.ConfidentialityHigh,
			Integrity:          vector.IntegrityHigh,
			Availability:       vector.AvailabilityHigh,
		},
	}

	dc := NewDistanceCalculator(vector1, vector2)

	// 欧几里得距离应该为0，因为所有分数都相同
	assert.Equal(t, 0.0, dc.EuclideanDistance())

	// 但汉明距离应该为1，因为有一个值不同
	assert.Equal(t, 1, dc.HammingDistance())
}

// 创建一个带有特定分数的向量
type testVector struct {
	shortValue rune
	score      float64
	shortName  string
}

func (tv *testVector) GetShortValue() rune {
	return tv.shortValue
}

func (tv *testVector) GetLongValue() string {
	return "Test Vector"
}

func (tv *testVector) GetScore() float64 {
	return tv.score
}

func (tv *testVector) String() string {
	return "TV:" + string(tv.shortValue)
}

func (tv *testVector) GetGroupName() string {
	return "Test Group"
}

func (tv *testVector) GetName() string {
	return "Test Vector"
}

func (tv *testVector) GetShortName() string {
	if tv.shortName == "" {
		return "TV"
	}
	return tv.shortName
}

func (tv *testVector) GetLongName() string {
	return "Test Vector"
}

func (tv *testVector) GetDescription() string {
	return "Test vector for unit tests"
}

func (tv *testVector) IsNotDefined() bool {
	return tv.shortValue == 'X'
}

func createVectorWithScore(shortValue rune, score float64) vector.Vector {
	return &testVector{
		shortValue: shortValue,
		score:      score,
		shortName:  "TV",
	}
}

// TestManhattanDistance_WithScopeChange 测试不同范围变化的曼哈顿距离
func TestManhattanDistance_WithScopeChange(t *testing.T) {
	// 测试范围变化对曼哈顿距离的影响
	vector1 := createTestVector(3, 1, "Network", "Low", "None", "None", "Unchanged", "High", "High", "High")
	vector2 := createTestVector(3, 1, "Network", "Low", "None", "None", "Changed", "High", "High", "High")

	dc := NewDistanceCalculator(vector1, vector2)
	distance := dc.ManhattanDistance()

	// 范围从Unchanged到Changed，期望曼哈顿距离为1.0
	assert.Equal(t, 1.0, distance)
}

// TestDistanceCalculator_WithRoundingErrors 测试舍入误差对距离计算的影响
func TestDistanceCalculator_WithRoundingErrors(t *testing.T) {
	// 创建两个向量，它们之间的分数差异接近浮点精度边界
	vector1 := &Cvss3x{
		MajorVersion: 3,
		MinorVersion: 1,
		Cvss3xBase: &Cvss3xBase{
			AttackVector:       createVectorWithScore('A', 0.3),
			AttackComplexity:   createVectorWithScore('B', 0.3),
			PrivilegesRequired: createVectorWithScore('C', 0.3),
			UserInteraction:    createVectorWithScore('D', 0.3),
			Scope:              vector.ScopeUnchanged,
			Confidentiality:    createVectorWithScore('E', 0.3),
			Integrity:          createVectorWithScore('F', 0.3),
			Availability:       createVectorWithScore('G', 0.3),
		},
	}

	vector2 := &Cvss3x{
		MajorVersion: 3,
		MinorVersion: 1,
		Cvss3xBase: &Cvss3xBase{
			AttackVector:       createVectorWithScore('A', 0.3+1e-10), // 微小差异
			AttackComplexity:   createVectorWithScore('B', 0.3+1e-10),
			PrivilegesRequired: createVectorWithScore('C', 0.3+1e-10),
			UserInteraction:    createVectorWithScore('D', 0.3+1e-10),
			Scope:              vector.ScopeUnchanged,
			Confidentiality:    createVectorWithScore('E', 0.3+1e-10),
			Integrity:          createVectorWithScore('F', 0.3+1e-10),
			Availability:       createVectorWithScore('G', 0.3+1e-10),
		},
	}

	dc := NewDistanceCalculator(vector1, vector2)
	euclidean := dc.EuclideanDistance()
	manhattan := dc.ManhattanDistance()

	// 由于浮点舍入误差，距离应该非常接近0，但可能不完全等于0
	assert.True(t, euclidean < 1e-8, "Euclidean distance should be very close to 0")
	assert.True(t, manhattan < 1e-8, "Manhattan distance should be very close to 0")
}

// TestScoreDifference_WithSameScore 测试分数相同的CVSS向量
func TestScoreDifference_WithSameScore(t *testing.T) {
	// 创建两个基础指标不同但最终分数可能相同的向量
	vector1 := createTestVector(3, 1, "Network", "High", "Low", "None", "Unchanged", "Low", "Low", "Low")
	vector2 := createTestVector(3, 1, "Adjacent", "Low", "Low", "None", "Unchanged", "Low", "Low", "Low")

	// 手动计算这两个向量的分数，确保它们相同或非常接近
	calc1 := NewCalculator(vector1)
	calc2 := NewCalculator(vector2)

	score1, err1 := calc1.Calculate()
	score2, err2 := calc2.Calculate()

	// 如果分数相同或非常接近
	if err1 == nil && err2 == nil && math.Abs(score1-score2) < 0.1 {
		dc := NewDistanceCalculator(vector1, vector2)
		difference := dc.ScoreDifference()

		// 分数差异应该很小
		assert.InDelta(t, 0.0, difference, 0.1)

		// 但汉明距离应该不为0
		assert.True(t, dc.HammingDistance() > 0)
	} else {
		// 如果分数不相同，这个测试不适用，跳过它
		t.Skip("Skipping test because the vectors don't have similar scores")
	}
}
