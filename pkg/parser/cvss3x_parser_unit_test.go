package parser

import (
	"strings"
	"testing"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCvss3xParser_readMagicHead 测试读取魔术头部
func TestCvss3xParser_readMagicHead(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected error
		index    int
	}{
		{
			name:     "Valid Magic Head",
			input:    "CVSS:3.1/AV:N/AC:L",
			expected: nil,
			index:    5, // 读取完 CVSS: 后的索引
		},
		{
			name:     "Valid Magic Head Lowercase",
			input:    "cvss:3.1/AV:N/AC:L",
			expected: nil,
			index:    5,
		},
		{
			name:     "Invalid Magic Head",
			input:    "CVS:3.1/AV:N/AC:L",
			expected: ErrParserMagicHead,
			index:    0,
		},
		{
			name:     "Empty String",
			input:    "",
			expected: ErrParserMagicHead,
			index:    0,
		},
		{
			name:     "Too Short",
			input:    "CVSS",
			expected: ErrParserMagicHead,
			index:    0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parser := NewCvss3xParser(tc.input)
			err := parser.readMagicHead()
			if tc.expected == nil {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Equal(t, tc.expected, err)
			}
			assert.Equal(t, tc.index, parser.i)
		})
	}
}

// TestCvss3xParser_readVersion 测试读取版本号
func TestCvss3xParser_readVersion(t *testing.T) {
	testCases := []struct {
		name             string
		input            string
		startIndex       int
		expectedError    bool
		expectedMajor    int
		expectedMinor    int
		expectedEndIndex int
	}{
		{
			name:             "Valid Version 3.1",
			input:            "3.1/AV:N/AC:L",
			startIndex:       0,
			expectedError:    false,
			expectedMajor:    3,
			expectedMinor:    1,
			expectedEndIndex: 3,
		},
		{
			name:             "Valid Version 3.0",
			input:            "3.0/AV:N/AC:L",
			startIndex:       0,
			expectedError:    false,
			expectedMajor:    3,
			expectedMinor:    0,
			expectedEndIndex: 3,
		},
		{
			name:             "Invalid Version Format",
			input:            "3/AV:N/AC:L",
			startIndex:       0,
			expectedError:    true,
			expectedMajor:    0,
			expectedMinor:    0,
			expectedEndIndex: 0,
		},
		{
			name:             "Empty Version",
			input:            "/AV:N/AC:L",
			startIndex:       0,
			expectedError:    true,
			expectedMajor:    0,
			expectedMinor:    0,
			expectedEndIndex: 0,
		},
		{
			name:             "Non-numeric Version",
			input:            "a.b/AV:N/AC:L",
			startIndex:       0,
			expectedError:    true,
			expectedMajor:    0,
			expectedMinor:    0,
			expectedEndIndex: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parser := NewCvss3xParser(tc.input)
			parser.i = tc.startIndex
			parser.cvss3x = cvss.NewCvss3x()
			err := parser.readVersion()

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedMajor, parser.cvss3x.MajorVersion)
				assert.Equal(t, tc.expectedMinor, parser.cvss3x.MinorVersion)
				assert.Equal(t, tc.expectedEndIndex, parser.i)
			}
		})
	}
}

// TestCvss3xParser_readMajorVersion 测试读取主版本号
func TestCvss3xParser_readMajorVersion(t *testing.T) {
	testCases := []struct {
		name           string
		input          string
		expectedError  bool
		expectedMajor  int
		expectedEndIdx int
	}{
		{
			name:           "Valid Major Version",
			input:          "3.1/AV:N",
			expectedError:  false,
			expectedMajor:  3,
			expectedEndIdx: 2,
		},
		{
			name:           "Empty String",
			input:          "",
			expectedError:  true,
			expectedMajor:  0,
			expectedEndIdx: 0,
		},
		{
			name:           "No Dot",
			input:          "3/AV:N",
			expectedError:  true,
			expectedMajor:  0,
			expectedEndIdx: 6,
		},
		{
			name:           "Non-numeric",
			input:          "X.1/AV:N",
			expectedError:  true,
			expectedMajor:  0,
			expectedEndIdx: 2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parser := NewCvss3xParser(tc.input)
			majorVersion, err := parser.readMajorVersion()

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedMajor, majorVersion)
			}
			assert.Equal(t, tc.expectedEndIdx, parser.i)
		})
	}
}

// TestCvss3xParser_readMinorVersion 测试读取副版本号
func TestCvss3xParser_readMinorVersion(t *testing.T) {
	testCases := []struct {
		name           string
		input          string
		startIdx       int
		expectedError  bool
		expectedMinor  int
		expectedEndIdx int
	}{
		{
			name:           "Valid Minor Version",
			input:          "3.1/AV:N",
			startIdx:       2,
			expectedError:  false,
			expectedMinor:  1,
			expectedEndIdx: 3,
		},
		{
			name:           "Valid Minor Version No Slash",
			input:          "3.10",
			startIdx:       2,
			expectedError:  false,
			expectedMinor:  10,
			expectedEndIdx: 4,
		},
		{
			name:           "Empty String",
			input:          "",
			startIdx:       0,
			expectedError:  true,
			expectedMinor:  0,
			expectedEndIdx: 0,
		},
		{
			name:           "Non-numeric",
			input:          "3.x/AV:N",
			startIdx:       2,
			expectedError:  true,
			expectedMinor:  0,
			expectedEndIdx: 3,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parser := NewCvss3xParser(tc.input)
			parser.i = tc.startIdx
			minorVersion, err := parser.readMinorVersion()

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedMinor, minorVersion)
			}
			assert.Equal(t, tc.expectedEndIdx, parser.i)
		})
	}
}

// TestCvss3xParser_readKey 测试读取键
func TestCvss3xParser_readKey(t *testing.T) {
	testCases := []struct {
		name           string
		input          string
		startIdx       int
		expectedError  bool
		expectedKey    string
		expectedEndIdx int
	}{
		{
			name:           "Valid Key",
			input:          "AV:N/AC:L",
			startIdx:       0,
			expectedError:  false,
			expectedKey:    "AV",
			expectedEndIdx: 2,
		},
		{
			name:           "Valid Key Without Value",
			input:          "AV:",
			startIdx:       0,
			expectedError:  false,
			expectedKey:    "AV",
			expectedEndIdx: 2,
		},
		{
			name:           "Empty String",
			input:          "",
			startIdx:       0,
			expectedError:  true,
			expectedKey:    "",
			expectedEndIdx: 0,
		},
		{
			name:           "No Colon",
			input:          "AV/AC:L",
			startIdx:       0,
			expectedError:  false, // 会读取到 '/'，认为是 key
			expectedKey:    "AV/AC",
			expectedEndIdx: 5,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parser := NewCvss3xParser(tc.input)
			parser.i = tc.startIdx
			key, err := parser.readKey()

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedKey, key)
			}
			assert.Equal(t, tc.expectedEndIdx, parser.i)
		})
	}
}

// TestCvss3xParser_readValue 测试读取值
func TestCvss3xParser_readValue(t *testing.T) {
	testCases := []struct {
		name           string
		input          string
		startIdx       int
		expectedError  bool
		expectedValue  string
		expectedEndIdx int
	}{
		{
			name:           "Valid Value",
			input:          ":N/AC:L",
			startIdx:       0,
			expectedError:  false,
			expectedValue:  "N",
			expectedEndIdx: 2,
		},
		{
			name:           "Valid Value End of String",
			input:          ":HIGH",
			startIdx:       0,
			expectedError:  false,
			expectedValue:  "HIGH",
			expectedEndIdx: 5,
		},
		{
			name:           "No Colon",
			input:          "N/AC:L",
			startIdx:       0,
			expectedError:  true,
			expectedValue:  "",
			expectedEndIdx: 1,
		},
		{
			name:           "Empty String",
			input:          "",
			startIdx:       0,
			expectedError:  true,
			expectedValue:  "",
			expectedEndIdx: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parser := NewCvss3xParser(tc.input)
			parser.i = tc.startIdx
			value, err := parser.readValue()

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedValue, value)
			}
			assert.Equal(t, tc.expectedEndIdx, parser.i)
		})
	}
}

// TestCvss3xParser_mapVectorToStruct 测试向量映射到结构体
func TestCvss3xParser_mapVectorToStruct(t *testing.T) {
	testCases := []struct {
		name          string
		key           string
		value         string
		expectedError bool
		checkField    func(t *testing.T, parser *Cvss3xParser)
	}{
		{
			name:          "Attack Vector",
			key:           "AV",
			value:         "N",
			expectedError: false,
			checkField: func(t *testing.T, parser *Cvss3xParser) {
				assert.NotNil(t, parser.cvss3x.Cvss3xBase.AttackVector)
				assert.Equal(t, "N", string(parser.cvss3x.Cvss3xBase.AttackVector.GetShortValue()))
			},
		},
		{
			name:          "Attack Complexity",
			key:           "AC",
			value:         "L",
			expectedError: false,
			checkField: func(t *testing.T, parser *Cvss3xParser) {
				assert.NotNil(t, parser.cvss3x.Cvss3xBase.AttackComplexity)
				assert.Equal(t, "L", string(parser.cvss3x.Cvss3xBase.AttackComplexity.GetShortValue()))
			},
		},
		{
			name:          "Exploit Code Maturity",
			key:           "E",
			value:         "F",
			expectedError: false,
			checkField: func(t *testing.T, parser *Cvss3xParser) {
				assert.NotNil(t, parser.cvss3x.Cvss3xTemporal.ExploitCodeMaturity)
				assert.Equal(t, "F", string(parser.cvss3x.Cvss3xTemporal.ExploitCodeMaturity.GetShortValue()))
			},
		},
		{
			name:          "Invalid Vector Key",
			key:           "XX",
			value:         "N",
			expectedError: true,
			checkField: func(t *testing.T, parser *Cvss3xParser) {
				// 不需要检查字段，因为期望会出错
			},
		},
		{
			name:          "Invalid Vector Value",
			key:           "AV",
			value:         "Z",
			expectedError: true,
			checkField: func(t *testing.T, parser *Cvss3xParser) {
				// 不需要检查字段，因为期望会出错
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parser := NewCvss3xParser("CVSS:3.1/AV:N")
			parser.cvss3x = cvss.NewCvss3x()
			err := parser.mapVectorToStruct(tc.key, tc.value)

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				tc.checkField(t, parser)
			}
		})
	}
}

// TestCvss3xParser_ParseDetailed 测试完整解析过程
func TestCvss3xParser_ParseDetailed(t *testing.T) {
	testCases := []struct {
		name          string
		input         string
		expectedError bool
		checkResults  func(t *testing.T, result *cvss.Cvss3x, err error)
	}{
		{
			name:          "Valid CVSS String - Base Only",
			input:         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			expectedError: false,
			checkResults: func(t *testing.T, result *cvss.Cvss3x, err error) {
				require.NoError(t, err)
				assert.Equal(t, 3, result.MajorVersion)
				assert.Equal(t, 1, result.MinorVersion)
				assert.Equal(t, 'N', result.Cvss3xBase.AttackVector.GetShortValue())
				assert.Equal(t, 'L', result.Cvss3xBase.AttackComplexity.GetShortValue())
				assert.Equal(t, 'N', result.Cvss3xBase.PrivilegesRequired.GetShortValue())
				assert.Equal(t, 'N', result.Cvss3xBase.UserInteraction.GetShortValue())
				assert.Equal(t, 'U', result.Cvss3xBase.Scope.GetShortValue())
				assert.Equal(t, 'H', result.Cvss3xBase.Confidentiality.GetShortValue())
				assert.Equal(t, 'H', result.Cvss3xBase.Integrity.GetShortValue())
				assert.Equal(t, 'H', result.Cvss3xBase.Availability.GetShortValue())
			},
		},
		{
			name:          "Valid CVSS String - With Temporal",
			input:         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C",
			expectedError: false,
			checkResults: func(t *testing.T, result *cvss.Cvss3x, err error) {
				require.NoError(t, err)
				assert.Equal(t, 3, result.MajorVersion)
				assert.Equal(t, 1, result.MinorVersion)
				assert.Equal(t, 'F', result.Cvss3xTemporal.ExploitCodeMaturity.GetShortValue())
				assert.Equal(t, 'O', result.Cvss3xTemporal.RemediationLevel.GetShortValue())
				assert.Equal(t, 'C', result.Cvss3xTemporal.ReportConfidence.GetShortValue())
			},
		},
		{
			name:          "Valid CVSS String - With Environmental",
			input:         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:M/AR:L",
			expectedError: false,
			checkResults: func(t *testing.T, result *cvss.Cvss3x, err error) {
				require.NoError(t, err)
				assert.Equal(t, 3, result.MajorVersion)
				assert.Equal(t, 1, result.MinorVersion)
				assert.Equal(t, 'H', result.Cvss3xEnvironmental.ConfidentialityRequirement.GetShortValue())
				assert.Equal(t, 'M', result.Cvss3xEnvironmental.IntegrityRequirement.GetShortValue())
				assert.Equal(t, 'L', result.Cvss3xEnvironmental.AvailabilityRequirement.GetShortValue())
			},
		},
		{
			name:          "Invalid CVSS String - No Magic Head",
			input:         "CS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			expectedError: true,
			checkResults: func(t *testing.T, result *cvss.Cvss3x, err error) {
				assert.Error(t, err)
				assert.True(t, strings.Contains(err.Error(), "magic head"))
			},
		},
		{
			name:          "Invalid CVSS String - Invalid Version",
			input:         "CVSS:X.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			expectedError: true,
			checkResults: func(t *testing.T, result *cvss.Cvss3x, err error) {
				assert.Error(t, err)
			},
		},
		{
			name:          "Invalid CVSS String - Missing Slash after Version",
			input:         "CVSS:3.1AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			expectedError: true,
			checkResults: func(t *testing.T, result *cvss.Cvss3x, err error) {
				assert.Error(t, err)
				assert.True(t, strings.Contains(err.Error(), "invalid syntax"))
			},
		},
		{
			name:          "Invalid CVSS String - Invalid Vector Key",
			input:         "CVSS:3.1/XX:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			expectedError: true,
			checkResults: func(t *testing.T, result *cvss.Cvss3x, err error) {
				assert.Error(t, err)
			},
		},
		{
			name:          "Invalid CVSS String - Invalid Vector Value",
			input:         "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			expectedError: true,
			checkResults: func(t *testing.T, result *cvss.Cvss3x, err error) {
				assert.Error(t, err)
			},
		},
		{
			name:          "Empty String",
			input:         "",
			expectedError: true,
			checkResults: func(t *testing.T, result *cvss.Cvss3x, err error) {
				assert.Error(t, err)
			},
		},
		{
			name:          "Invalid CVSS String - Invalid Version (0.0)",
			input:         "CVSS:0.0/S:C",
			expectedError: true,
			checkResults: func(t *testing.T, result *cvss.Cvss3x, err error) {
				assert.Error(t, err)
				assert.True(t, strings.Contains(err.Error(), "major version"))
			},
		},
		{
			name:          "Invalid CVSS String - Invalid Major Version (4.1)",
			input:         "CVSS:4.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			expectedError: true,
			checkResults: func(t *testing.T, result *cvss.Cvss3x, err error) {
				assert.Error(t, err)
				assert.True(t, strings.Contains(err.Error(), "major version"))
			},
		},
		{
			name:          "Invalid CVSS String - Invalid Minor Version (3.2)",
			input:         "CVSS:3.2/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			expectedError: true,
			checkResults: func(t *testing.T, result *cvss.Cvss3x, err error) {
				assert.Error(t, err)
				assert.True(t, strings.Contains(err.Error(), "minor version"))
			},
		},
		{
			name:          "Partial String",
			input:         "CVSS:3.1",
			expectedError: true,
			checkResults: func(t *testing.T, result *cvss.Cvss3x, err error) {
				assert.Error(t, err)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parser := NewCvss3xParser(tc.input)
			result, err := parser.Parse()

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			tc.checkResults(t, result, err)
		})
	}
}

// TestCvss3xParser_isNotEnd 测试isNotEnd方法
func TestCvss3xParser_isNotEnd(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		index    int
		expected bool
	}{
		{
			name:     "Not at End",
			input:    "CVSS:3.1",
			index:    5,
			expected: true,
		},
		{
			name:     "At End",
			input:    "CVSS:3.1",
			index:    8,
			expected: false,
		},
		{
			name:     "Beyond End",
			input:    "CVSS:3.1",
			index:    10,
			expected: false,
		},
		{
			name:     "Empty String",
			input:    "",
			index:    0,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parser := NewCvss3xParser(tc.input)
			parser.i = tc.index
			assert.Equal(t, tc.expected, parser.isNotEnd())
		})
	}
}

// TestCvss3xParser_read 测试read方法
func TestCvss3xParser_read(t *testing.T) {
	testCases := []struct {
		name           string
		input          string
		startIdx       int
		expected       rune
		expectedEndIdx int
	}{
		{
			name:           "Valid Character",
			input:          "CVSS",
			startIdx:       0,
			expected:       'C',
			expectedEndIdx: 1,
		},
		{
			name:           "Last Character",
			input:          "CVSS",
			startIdx:       3,
			expected:       'S',
			expectedEndIdx: 4,
		},
		{
			name:           "At End",
			input:          "CVSS",
			startIdx:       4,
			expected:       0,
			expectedEndIdx: 4,
		},
		{
			name:           "Beyond End",
			input:          "CVSS",
			startIdx:       5,
			expected:       0,
			expectedEndIdx: 5,
		},
		{
			name:           "Empty String",
			input:          "",
			startIdx:       0,
			expected:       0,
			expectedEndIdx: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parser := NewCvss3xParser(tc.input)
			parser.i = tc.startIdx
			assert.Equal(t, tc.expected, parser.read())
			assert.Equal(t, tc.expectedEndIdx, parser.i)
		})
	}
}
