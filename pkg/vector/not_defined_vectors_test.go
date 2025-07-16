package vector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNotDefinedVectors 测试所有的NotDefined向量
func TestNotDefinedVectors(t *testing.T) {
	// 测试各NotDefined向量的共同特性
	notDefinedVectors := []struct {
		name     string
		vector   Vector
		group    string
		shortVal rune
		longVal  string
		score    float64
	}{
		{
			name:     "AttackVectorNotDefined",
			vector:   AttackVectorNotDefined,
			group:    "Environmental",
			shortVal: 'X',
			longVal:  "Not Defined",
			score:    1.0,
		},
		{
			name:     "AttackComplexityNotDefined",
			vector:   AttackComplexityNotDefined,
			group:    "Environmental",
			shortVal: 'X',
			longVal:  "Not Defined",
			score:    1.0,
		},
		{
			name:     "PrivilegesRequiredNotDefined",
			vector:   PrivilegesRequiredNotDefined,
			group:    "Environmental",
			shortVal: 'X',
			longVal:  "Not Defined",
			score:    1.0,
		},
		{
			name:     "UserInteractionNotDefined",
			vector:   UserInteractionNotDefined,
			group:    "Environmental",
			shortVal: 'X',
			longVal:  "Not Defined",
			score:    1.0,
		},
		{
			name:     "ScopeNotDefined",
			vector:   ScopeNotDefined,
			group:    "Environmental",
			shortVal: 'X',
			longVal:  "Not Defined",
			score:    1.0,
		},
		{
			name:     "ConfidentialityNotDefined",
			vector:   ConfidentialityNotDefined,
			group:    "Environmental",
			shortVal: 'X',
			longVal:  "Not Defined",
			score:    1.0,
		},
		{
			name:     "IntegrityNotDefined",
			vector:   IntegrityNotDefined,
			group:    "Environmental",
			shortVal: 'X',
			longVal:  "Not Defined",
			score:    1.0,
		},
		{
			name:     "AvailabilityNotDefined",
			vector:   AvailabilityNotDefined,
			group:    "Environmental",
			shortVal: 'X',
			longVal:  "Not Defined",
			score:    1.0,
		},
	}

	for _, tc := range notDefinedVectors {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.group, tc.vector.GetGroupName())
			assert.Equal(t, tc.shortVal, tc.vector.GetShortValue())
			assert.Equal(t, tc.longVal, tc.vector.GetLongValue())
			assert.Equal(t, tc.score, tc.vector.GetScore())
			assert.Contains(t, tc.vector.GetDescription(), "未定义")
		})
	}
}

// TestAttackVectorNotDefined 测试攻击向量未定义
func TestAttackVectorNotDefined(t *testing.T) {
	v := AttackVectorNotDefined
	assert.Equal(t, "MAV", v.GetShortName())
	assert.Equal(t, "Modified Attack Vector", v.GetLongName())
	assert.Equal(t, 'X', v.GetShortValue())
	assert.Equal(t, "Not Defined", v.GetLongValue())
	assert.Equal(t, 1.0, v.GetScore())
	assert.Equal(t, "Environmental", v.GetGroupName())
	assert.Contains(t, v.GetDescription(), "未定义")
	assert.Equal(t, "MAV:X", v.String())
}

// TestAttackComplexityNotDefined 测试攻击复杂性未定义
func TestAttackComplexityNotDefined(t *testing.T) {
	v := AttackComplexityNotDefined
	assert.Equal(t, "MAC", v.GetShortName())
	assert.Equal(t, "Modified Attack Complexity", v.GetLongName())
	assert.Equal(t, 'X', v.GetShortValue())
	assert.Equal(t, "Not Defined", v.GetLongValue())
	assert.Equal(t, 1.0, v.GetScore())
	assert.Equal(t, "Environmental", v.GetGroupName())
	assert.Contains(t, v.GetDescription(), "未定义")
	assert.Equal(t, "MAC:X", v.String())
}

// TestPrivilegesRequiredNotDefined 测试特权要求未定义
func TestPrivilegesRequiredNotDefined(t *testing.T) {
	v := PrivilegesRequiredNotDefined
	assert.Equal(t, "MPR", v.GetShortName())
	assert.Equal(t, "Modified Privileges Required", v.GetLongName())
	assert.Equal(t, 'X', v.GetShortValue())
	assert.Equal(t, "Not Defined", v.GetLongValue())
	assert.Equal(t, 1.0, v.GetScore())
	assert.Equal(t, "Environmental", v.GetGroupName())
	assert.Contains(t, v.GetDescription(), "未定义")
	assert.Equal(t, "MPR:X", v.String())
}

// TestUserInteractionNotDefined 测试用户交互未定义
func TestUserInteractionNotDefined(t *testing.T) {
	v := UserInteractionNotDefined
	assert.Equal(t, "MUI", v.GetShortName())
	assert.Equal(t, "Modified User Interaction", v.GetLongName())
	assert.Equal(t, 'X', v.GetShortValue())
	assert.Equal(t, "Not Defined", v.GetLongValue())
	assert.Equal(t, 1.0, v.GetScore())
	assert.Equal(t, "Environmental", v.GetGroupName())
	assert.Contains(t, v.GetDescription(), "未定义")
	assert.Equal(t, "MUI:X", v.String())
}

// TestScopeNotDefined 测试范围未定义
func TestScopeNotDefined(t *testing.T) {
	v := ScopeNotDefined
	assert.Equal(t, "MS", v.GetShortName())
	assert.Equal(t, "Modified Scope", v.GetLongName())
	assert.Equal(t, 'X', v.GetShortValue())
	assert.Equal(t, "Not Defined", v.GetLongValue())
	assert.Equal(t, 1.0, v.GetScore())
	assert.Equal(t, "Environmental", v.GetGroupName())
	assert.Contains(t, v.GetDescription(), "未定义")
	assert.Equal(t, "MS:X", v.String())
}

// TestConfidentialityNotDefined 测试机密性未定义
func TestConfidentialityNotDefined(t *testing.T) {
	v := ConfidentialityNotDefined
	assert.Equal(t, "MC", v.GetShortName())
	assert.Equal(t, "Modified Confidentiality", v.GetLongName())
	assert.Equal(t, 'X', v.GetShortValue())
	assert.Equal(t, "Not Defined", v.GetLongValue())
	assert.Equal(t, 1.0, v.GetScore())
	assert.Equal(t, "Environmental", v.GetGroupName())
	assert.Contains(t, v.GetDescription(), "未定义")
	assert.Equal(t, "MC:X", v.String())
}

// TestIntegrityNotDefined 测试完整性未定义
func TestIntegrityNotDefined(t *testing.T) {
	v := IntegrityNotDefined
	assert.Equal(t, "MI", v.GetShortName())
	assert.Equal(t, "Modified Integrity", v.GetLongName())
	assert.Equal(t, 'X', v.GetShortValue())
	assert.Equal(t, "Not Defined", v.GetLongValue())
	assert.Equal(t, 1.0, v.GetScore())
	assert.Equal(t, "Environmental", v.GetGroupName())
	assert.Contains(t, v.GetDescription(), "未定义")
	assert.Equal(t, "MI:X", v.String())
}

// TestAvailabilityNotDefined 测试可用性未定义
func TestAvailabilityNotDefined(t *testing.T) {
	v := AvailabilityNotDefined
	assert.Equal(t, "MA", v.GetShortName())
	assert.Equal(t, "Modified Availability", v.GetLongName())
	assert.Equal(t, 'X', v.GetShortValue())
	assert.Equal(t, "Not Defined", v.GetLongValue())
	assert.Equal(t, 1.0, v.GetScore())
	assert.Equal(t, "Environmental", v.GetGroupName())
	assert.Contains(t, v.GetDescription(), "未定义")
	assert.Equal(t, "MA:X", v.String())
}

// TestNotDefinedVectorsInFactory 测试工厂方法获取NotDefined向量
func TestNotDefinedVectorsInFactory(t *testing.T) {
	// 测试通过工厂方法获取各NotDefined向量
	testCases := []struct {
		name       string
		factoryFn  func(rune) (Vector, error)
		shortValue rune
		expected   Vector
	}{
		{
			name:       "GetModifiedAttackVector NotDefined",
			factoryFn:  GetModifiedAttackVector,
			shortValue: 'X',
			expected:   AttackVectorNotDefined,
		},
		{
			name:       "GetModifiedAttackComplexity NotDefined",
			factoryFn:  GetModifiedAttackComplexity,
			shortValue: 'X',
			expected:   AttackComplexityNotDefined,
		},
		{
			name:       "GetModifiedPrivilegesRequired NotDefined",
			factoryFn:  GetModifiedPrivilegesRequired,
			shortValue: 'X',
			expected:   PrivilegesRequiredNotDefined,
		},
		{
			name:       "GetModifiedUserInteraction NotDefined",
			factoryFn:  GetModifiedUserInteraction,
			shortValue: 'X',
			expected:   UserInteractionNotDefined,
		},
		{
			name:       "GetModifiedScope NotDefined",
			factoryFn:  GetModifiedScope,
			shortValue: 'X',
			expected:   ScopeNotDefined,
		},
		{
			name:       "GetModifiedConfidentiality NotDefined",
			factoryFn:  GetModifiedConfidentiality,
			shortValue: 'X',
			expected:   ConfidentialityNotDefined,
		},
		{
			name:       "GetModifiedIntegrity NotDefined",
			factoryFn:  GetModifiedIntegrity,
			shortValue: 'X',
			expected:   IntegrityNotDefined,
		},
		{
			name:       "GetModifiedAvailability NotDefined",
			factoryFn:  GetModifiedAvailability,
			shortValue: 'X',
			expected:   AvailabilityNotDefined,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := tc.factoryFn(tc.shortValue)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, v)
		})
	}
}

// TestNotDefinedVectorsByShortName 测试通过短名称获取NotDefined向量
func TestNotDefinedVectorsByShortName(t *testing.T) {
	testCases := []struct {
		name      string
		shortName string
		value     string
		expected  Vector
	}{
		{
			name:      "MAV Not Defined",
			shortName: "MAV",
			value:     "X",
			expected:  AttackVectorNotDefined,
		},
		{
			name:      "MAC Not Defined",
			shortName: "MAC",
			value:     "X",
			expected:  AttackComplexityNotDefined,
		},
		{
			name:      "MPR Not Defined",
			shortName: "MPR",
			value:     "X",
			expected:  PrivilegesRequiredNotDefined,
		},
		{
			name:      "MUI Not Defined",
			shortName: "MUI",
			value:     "X",
			expected:  UserInteractionNotDefined,
		},
		{
			name:      "MS Not Defined",
			shortName: "MS",
			value:     "X",
			expected:  ScopeNotDefined,
		},
		{
			name:      "MC Not Defined",
			shortName: "MC",
			value:     "X",
			expected:  ConfidentialityNotDefined,
		},
		{
			name:      "MI Not Defined",
			shortName: "MI",
			value:     "X",
			expected:  IntegrityNotDefined,
		},
		{
			name:      "MA Not Defined",
			shortName: "MA",
			value:     "X",
			expected:  AvailabilityNotDefined,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := GetVectorByShortName(tc.shortName, tc.value)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, v)
		})
	}
}
