package vector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGetVectorByShortName 测试通过短名称获取向量
func TestGetVectorByShortName(t *testing.T) {
	testCases := []struct {
		name      string
		shortName string
		value     string
		wantErr   bool
		expected  Vector
	}{
		{
			name:      "Valid AV:N",
			shortName: "AV",
			value:     "N",
			wantErr:   false,
			expected:  AttackVectorNetwork,
		},
		{
			name:      "Valid AC:H",
			shortName: "AC",
			value:     "H",
			wantErr:   false,
			expected:  AttackComplexityHigh,
		},
		{
			name:      "Valid PR:L",
			shortName: "PR",
			value:     "L",
			wantErr:   false,
			expected:  PrivilegesRequiredLow,
		},
		{
			name:      "Valid UI:R",
			shortName: "UI",
			value:     "R",
			wantErr:   false,
			expected:  UserInteractionRequired,
		},
		{
			name:      "Valid S:C",
			shortName: "S",
			value:     "C",
			wantErr:   false,
			expected:  ScopeChanged,
		},
		{
			name:      "Valid C:H",
			shortName: "C",
			value:     "H",
			wantErr:   false,
			expected:  ConfidentialityHigh,
		},
		{
			name:      "Valid I:L",
			shortName: "I",
			value:     "L",
			wantErr:   false,
			expected:  IntegrityLow,
		},
		{
			name:      "Valid A:N",
			shortName: "A",
			value:     "N",
			wantErr:   false,
			expected:  AvailabilityNone,
		},
		{
			name:      "Valid E:F",
			shortName: "E",
			value:     "F",
			wantErr:   false,
			expected:  ExploitCodeMaturityFunctional,
		},
		{
			name:      "Valid RL:O",
			shortName: "RL",
			value:     "O",
			wantErr:   false,
			expected:  RemediationLevelOfficialFix,
		},
		{
			name:      "Valid RC:C",
			shortName: "RC",
			value:     "C",
			wantErr:   false,
			expected:  ReportConfidenceConfirmed,
		},
		{
			name:      "Valid CR:H",
			shortName: "CR",
			value:     "H",
			wantErr:   false,
			expected:  ConfidentialityRequirementHigh,
		},
		{
			name:      "Valid IR:M",
			shortName: "IR",
			value:     "M",
			wantErr:   false,
			expected:  IntegrityRequirementMedium,
		},
		{
			name:      "Valid AR:L",
			shortName: "AR",
			value:     "L",
			wantErr:   false,
			expected:  AvailabilityRequirementLow,
		},
		{
			name:      "Valid MAV:P",
			shortName: "MAV",
			value:     "P",
			wantErr:   false,
			expected:  ModifiedAttackVectorPhysical,
		},
		{
			name:      "Valid MAC:H",
			shortName: "MAC",
			value:     "H",
			wantErr:   false,
			expected:  ModifiedAttackComplexityHigh,
		},
		{
			name:      "Invalid ShortName",
			shortName: "ZZ",
			value:     "N",
			wantErr:   true,
			expected:  nil,
		},
		{
			name:      "Invalid Value",
			shortName: "AV",
			value:     "Z",
			wantErr:   true,
			expected:  nil,
		},
		{
			name:      "Too Long Value",
			shortName: "AV",
			value:     "NN",
			wantErr:   true,
			expected:  nil,
		},
		{
			name:      "Empty Value",
			shortName: "AV",
			value:     "",
			wantErr:   true,
			expected:  nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := GetVectorByShortName(tc.shortName, tc.value)

			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, v)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, v)
			}
		})
	}
}

// TestGetAttackVector 测试获取攻击向量
func TestGetAttackVector(t *testing.T) {
	testCases := []struct {
		name     string
		value    rune
		wantErr  bool
		expected Vector
	}{
		{
			name:     "Network",
			value:    'N',
			wantErr:  false,
			expected: AttackVectorNetwork,
		},
		{
			name:     "Adjacent",
			value:    'A',
			wantErr:  false,
			expected: AttackVectorAdjacent,
		},
		{
			name:     "Local",
			value:    'L',
			wantErr:  false,
			expected: AttackVectorLocal,
		},
		{
			name:     "Physical",
			value:    'P',
			wantErr:  false,
			expected: AttackVectorPhysical,
		},
		{
			name:     "Invalid",
			value:    'Z',
			wantErr:  true,
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := GetAttackVector(tc.value)

			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, v)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, v)
			}
		})
	}
}

// TestGetAttackComplexity 测试获取攻击复杂性
func TestGetAttackComplexity(t *testing.T) {
	testCases := []struct {
		name     string
		value    rune
		wantErr  bool
		expected Vector
	}{
		{
			name:     "Low",
			value:    'L',
			wantErr:  false,
			expected: AttackComplexityLow,
		},
		{
			name:     "High",
			value:    'H',
			wantErr:  false,
			expected: AttackComplexityHigh,
		},
		{
			name:     "Invalid",
			value:    'Z',
			wantErr:  true,
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := GetAttackComplexity(tc.value)

			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, v)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, v)
			}
		})
	}
}

// TestGetModifiedVectors 测试获取Modified向量方法
func TestGetModifiedVectors(t *testing.T) {
	// 测试Modified攻击向量
	t.Run("GetModifiedAttackVector", func(t *testing.T) {
		// 正常值
		v, err := GetModifiedAttackVector('N')
		assert.NoError(t, err)
		assert.Equal(t, ModifiedAttackVectorNetwork, v)

		// NotDefined值
		v, err = GetModifiedAttackVector('X')
		assert.NoError(t, err)
		assert.Equal(t, AttackVectorNotDefined, v)

		// 错误值
		v, err = GetModifiedAttackVector('Z')
		assert.Error(t, err)
		assert.Nil(t, v)
	})

	// 测试Modified攻击复杂性
	t.Run("GetModifiedAttackComplexity", func(t *testing.T) {
		// 正常值
		v, err := GetModifiedAttackComplexity('L')
		assert.NoError(t, err)
		assert.Equal(t, ModifiedAttackComplexityLow, v)

		// NotDefined值
		v, err = GetModifiedAttackComplexity('X')
		assert.NoError(t, err)
		assert.Equal(t, AttackComplexityNotDefined, v)

		// 错误值
		v, err = GetModifiedAttackComplexity('Z')
		assert.Error(t, err)
		assert.Nil(t, v)
	})

	// 测试Modified特权要求
	t.Run("GetModifiedPrivilegesRequired", func(t *testing.T) {
		// 正常值
		v, err := GetModifiedPrivilegesRequired('N')
		assert.NoError(t, err)
		assert.Equal(t, ModifiedPrivilegesRequiredNone, v)

		// NotDefined值
		v, err = GetModifiedPrivilegesRequired('X')
		assert.NoError(t, err)
		assert.Equal(t, PrivilegesRequiredNotDefined, v)

		// 错误值
		v, err = GetModifiedPrivilegesRequired('Z')
		assert.Error(t, err)
		assert.Nil(t, v)
	})
}

// TestGetEnvironmentalVectors 测试获取环境向量方法
func TestGetEnvironmentalVectors(t *testing.T) {
	// 测试机密性需求
	t.Run("GetConfidentialityRequirement", func(t *testing.T) {
		testCases := []struct {
			name     string
			value    rune
			wantErr  bool
			expected Vector
		}{
			{"NotDefined", 'X', false, ConfidentialityRequirementNotDefined},
			{"Low", 'L', false, ConfidentialityRequirementLow},
			{"Medium", 'M', false, ConfidentialityRequirementMedium},
			{"High", 'H', false, ConfidentialityRequirementHigh},
			{"Invalid", 'Z', true, nil},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				v, err := GetConfidentialityRequirement(tc.value)

				if tc.wantErr {
					assert.Error(t, err)
					assert.Nil(t, v)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, tc.expected, v)
				}
			})
		}
	})

	// 测试完整性需求
	t.Run("GetIntegrityRequirement", func(t *testing.T) {
		testCases := []struct {
			name     string
			value    rune
			wantErr  bool
			expected Vector
		}{
			{"NotDefined", 'X', false, IntegrityRequirementNotDefined},
			{"Low", 'L', false, IntegrityRequirementLow},
			{"Medium", 'M', false, IntegrityRequirementMedium},
			{"High", 'H', false, IntegrityRequirementHigh},
			{"Invalid", 'Z', true, nil},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				v, err := GetIntegrityRequirement(tc.value)

				if tc.wantErr {
					assert.Error(t, err)
					assert.Nil(t, v)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, tc.expected, v)
				}
			})
		}
	})

	// 测试可用性需求
	t.Run("GetAvailabilityRequirement", func(t *testing.T) {
		testCases := []struct {
			name     string
			value    rune
			wantErr  bool
			expected Vector
		}{
			{"NotDefined", 'X', false, AvailabilityRequirementNotDefined},
			{"Low", 'L', false, AvailabilityRequirementLow},
			{"Medium", 'M', false, AvailabilityRequirementMedium},
			{"High", 'H', false, AvailabilityRequirementHigh},
			{"Invalid", 'Z', true, nil},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				v, err := GetAvailabilityRequirement(tc.value)

				if tc.wantErr {
					assert.Error(t, err)
					assert.Nil(t, v)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, tc.expected, v)
				}
			})
		}
	})
}

// TestGetTemporalVectors 测试获取时间向量方法
func TestGetTemporalVectors(t *testing.T) {
	// 测试利用代码成熟度
	t.Run("GetExploitCodeMaturity", func(t *testing.T) {
		testCases := []struct {
			name     string
			value    rune
			wantErr  bool
			expected Vector
		}{
			{"NotDefined", 'X', false, ExploitCodeMaturityNotDefined},
			{"Unproven", 'U', false, ExploitCodeMaturityUnproven},
			{"PoC", 'P', false, ExploitCodeMaturityProofOfConcept},
			{"Functional", 'F', false, ExploitCodeMaturityFunctional},
			{"High", 'H', false, ExploitCodeMaturityHigh},
			{"Invalid", 'Z', true, nil},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				v, err := GetExploitCodeMaturity(tc.value)

				if tc.wantErr {
					assert.Error(t, err)
					assert.Nil(t, v)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, tc.expected, v)
				}
			})
		}
	})

	// 测试修复级别
	t.Run("GetRemediationLevel", func(t *testing.T) {
		testCases := []struct {
			name     string
			value    rune
			wantErr  bool
			expected Vector
		}{
			{"NotDefined", 'X', false, RemediationLevelNotDefined},
			{"OfficialFix", 'O', false, RemediationLevelOfficialFix},
			{"TemporaryFix", 'T', false, RemediationLevelTemporaryFix},
			{"Workaround", 'W', false, RemediationLevelWorkaround},
			{"Unavailable", 'U', false, RemediationLevelUnavailable},
			{"Invalid", 'Z', true, nil},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				v, err := GetRemediationLevel(tc.value)

				if tc.wantErr {
					assert.Error(t, err)
					assert.Nil(t, v)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, tc.expected, v)
				}
			})
		}
	})

	// 测试报告置信度
	t.Run("GetReportConfidence", func(t *testing.T) {
		testCases := []struct {
			name     string
			value    rune
			wantErr  bool
			expected Vector
		}{
			{"NotDefined", 'X', false, ReportConfidenceNotDefined},
			{"Unknown", 'U', false, ReportConfidenceUnknown},
			{"Reasonable", 'R', false, ReportConfidenceReasonable},
			{"Confirmed", 'C', false, ReportConfidenceConfirmed},
			{"Invalid", 'Z', true, nil},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				v, err := GetReportConfidence(tc.value)

				if tc.wantErr {
					assert.Error(t, err)
					assert.Nil(t, v)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, tc.expected, v)
				}
			})
		}
	})
}
