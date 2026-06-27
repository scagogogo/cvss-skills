package parser

import (
	"encoding/json"
	"testing"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Score 定义CVSS分数结构
type Score struct {
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
	TemporalScore         float64 `json:"temporalScore"`
	TemporalSeverity      string  `json:"temporalSeverity"`
	EnvironmentalScore    float64 `json:"environmentalScore"`
	EnvironmentalSeverity string  `json:"environmentalSeverity"`
}

// TestCvssToJSON 测试CVSS向量的JSON序列化
func TestCvssToJSON(t *testing.T) {
	testCases := []struct {
		name           string
		vector         string
		expectedFields []string
	}{
		{
			name:   "Base Metrics Only",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			expectedFields: []string{
				"version", "vectorString", "baseScore", "baseSeverity",
				"attackVector", "attackComplexity", "privilegesRequired", "userInteraction",
				"scope", "confidentiality", "integrity", "availability",
			},
		},
		{
			name:   "With Temporal Metrics",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C",
			expectedFields: []string{
				// Base fields
				"version", "vectorString", "baseScore", "baseSeverity",
				// Temporal fields
				"temporalScore", "temporalSeverity",
				"exploitCodeMaturity", "remediationLevel", "reportConfidence",
			},
		},
		{
			name:   "With Environmental Metrics",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:M/AR:L/MAV:A/MAC:H/MPR:L/MUI:N/MS:U/MC:L/MI:L/MA:L",
			expectedFields: []string{
				// Base fields
				"version", "vectorString", "baseScore", "baseSeverity",
				// Environmental fields
				"environmentalScore", "environmentalSeverity",
				"confidentialityRequirement", "integrityRequirement", "availabilityRequirement",
				"modifiedAttackVector", "modifiedAttackComplexity", "modifiedPrivilegesRequired",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parser := NewCvss3xParser(tc.vector)
			cvss3x, err := parser.Parse()
			require.NoError(t, err)

			// Create calculator and calculate scores
			calculator := cvss.NewCalculator(cvss3x)
			_, err = calculator.Calculate()
			require.NoError(t, err)

			// Get JSON output using ToJSON method
			jsonOutput, err := cvss3x.ToJSON(calculator)
			require.NoError(t, err)

			// Parse the JSON output
			var output map[string]interface{}
			err = json.Unmarshal(jsonOutput, &output)
			require.NoError(t, err)

			// Verify expected fields are present
			for _, field := range tc.expectedFields {
				if field == "attackVector" || field == "attackComplexity" ||
					field == "privilegesRequired" || field == "userInteraction" ||
					field == "scope" || field == "confidentiality" ||
					field == "integrity" || field == "availability" {
					// These fields are nested under metrics.base
					metrics := output["metrics"].(map[string]interface{})
					base := metrics["base"].(map[string]interface{})
					assert.Contains(t, base, field, "Expected field '%s' not found in base metrics", field)
				} else if field == "exploitCodeMaturity" || field == "remediationLevel" ||
					field == "reportConfidence" {
					// These fields are nested under metrics.temporal
					metrics := output["metrics"].(map[string]interface{})
					if temporal, ok := metrics["temporal"].(map[string]interface{}); ok {
						assert.Contains(t, temporal, field, "Expected field '%s' not found in temporal metrics", field)
					} else {
						assert.Fail(t, "Temporal metrics expected but not found")
					}
				} else if field == "confidentialityRequirement" || field == "integrityRequirement" ||
					field == "availabilityRequirement" || field == "modifiedAttackVector" ||
					field == "modifiedAttackComplexity" || field == "modifiedPrivilegesRequired" {
					// These fields are nested under metrics.environmental
					metrics := output["metrics"].(map[string]interface{})
					if environmental, ok := metrics["environmental"].(map[string]interface{}); ok {
						assert.Contains(t, environmental, field, "Expected field '%s' not found in environmental metrics", field)
					} else {
						assert.Fail(t, "Environmental metrics expected but not found")
					}
				} else {
					// These are top-level fields
					assert.Contains(t, output, field, "Expected field '%s' not found in JSON output", field)
				}
			}

			// Verify base values
			assert.Equal(t, tc.vector, output["vectorString"])
			assert.Equal(t, "3.1", output["version"])
		})
	}
}

// TestScoreJson 测试分数的JSON序列化和反序列化
func TestScoreJson(t *testing.T) {
	// 创建一个分数对象
	score := &Score{
		BaseScore:             9.8,
		BaseSeverity:          "Critical",
		TemporalScore:         9.0,
		TemporalSeverity:      "Critical",
		EnvironmentalScore:    9.9,
		EnvironmentalSeverity: "Critical",
	}

	// 序列化为JSON
	jsonBytes, err := json.Marshal(score)
	require.NoError(t, err)
	jsonStr := string(jsonBytes)

	// 验证序列化结果
	assert.Contains(t, jsonStr, `"baseScore":9.8`)
	assert.Contains(t, jsonStr, `"baseSeverity":"Critical"`)
	assert.Contains(t, jsonStr, `"temporalScore":9`)
	assert.Contains(t, jsonStr, `"temporalSeverity":"Critical"`)
	assert.Contains(t, jsonStr, `"environmentalScore":9.9`)
	assert.Contains(t, jsonStr, `"environmentalSeverity":"Critical"`)

	// 反序列化
	var newScore Score
	err = json.Unmarshal(jsonBytes, &newScore)
	require.NoError(t, err)

	// 验证反序列化结果
	assert.Equal(t, score.BaseScore, newScore.BaseScore)
	assert.Equal(t, score.BaseSeverity, newScore.BaseSeverity)
	assert.Equal(t, score.TemporalScore, newScore.TemporalScore)
	assert.Equal(t, score.TemporalSeverity, newScore.TemporalSeverity)
	assert.Equal(t, score.EnvironmentalScore, newScore.EnvironmentalScore)
	assert.Equal(t, score.EnvironmentalSeverity, newScore.EnvironmentalSeverity)
}

// TestVectorsInJsonOutput 测试从JSON输出中读取向量信息
func TestVectorsInJsonOutput(t *testing.T) {
	// Define test vector
	vector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C"

	// Parse vector
	parser := NewCvss3xParser(vector)
	cvss3x, err := parser.Parse()
	require.NoError(t, err)

	// Calculate scores
	calculator := cvss.NewCalculator(cvss3x)
	_, err = calculator.Calculate()
	require.NoError(t, err)

	// Get JSON output
	jsonOutput, err := cvss3x.ToJSON(calculator)
	require.NoError(t, err)

	// Parse the JSON
	var output map[string]interface{}
	err = json.Unmarshal(jsonOutput, &output)
	require.NoError(t, err)

	// Check specific values
	// Note: These assertions are based on actual calculated values
	assert.InDelta(t, 10.0, output["baseScore"].(float64), 0.1)
	assert.InDelta(t, 10.0, output["temporalScore"].(float64), 0.2)
}

// TestSimplifiedJsonExample 测试简单的JSON示例
func TestSimplifiedJsonExample(t *testing.T) {
	// 解析向量
	vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
	parser := NewCvss3xParser(vectorStr)
	cvss3x, err := parser.Parse()
	require.NoError(t, err)

	// 计算分数
	calculator := cvss.NewCalculator(cvss3x)
	baseScore, err := calculator.Calculate()
	require.NoError(t, err)

	// 使用ToJSON方法序列化为JSON
	jsonBytes, err := cvss3x.ToJSON(calculator)
	require.NoError(t, err)

	// 验证JSON包含所有必要信息
	jsonStr := string(jsonBytes)
	assert.Contains(t, jsonStr, `"version": "3.1"`)
	assert.Contains(t, jsonStr, `"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"`)
	assert.Contains(t, jsonStr, `"baseScore"`)
	assert.Contains(t, jsonStr, `"baseSeverity"`)
	assert.Contains(t, jsonStr, `"metrics"`)
	assert.Contains(t, jsonStr, `"base"`)

	// 验证基础分数
	assert.InDelta(t, 10.0, baseScore, 0.2)
}
