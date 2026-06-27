package parser

import (
	"testing"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/stretchr/testify/assert"
)

func TestCvss3xParser_Parse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "Valid CVSS 3.1 vector string",
			input:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantErr: false,
		},
		{
			name:    "Valid CVSS 3.0 vector string",
			input:   "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",
			wantErr: false,
		},
		{
			name:    "Invalid CVSS string format",
			input:   "Invalid-CVSS-String",
			wantErr: true,
		},
		{
			name:    "Empty CVSS string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewCvss3xParser(tt.input)
			result, err := p.Parse()

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)

			// 验证解析后可以正确转回字符串格式
			if !tt.wantErr {
				assert.Contains(t, result.String(), "AV:")
			}
		})
	}
}

func TestCvss3xParser_ParseAndCalculate(t *testing.T) {
	// 这是CVSS 3.1中的一些标准示例向量
	vectors := []struct {
		vector       string
		expectedBase float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8}, // 关键级别
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8}, // 高级别
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L", 5.0}, // 中级别 (根据CVSS 3.1公式计算得5.0)
		{"CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N", 3.1}, // 低级别
	}

	for _, v := range vectors {
		t.Run(v.vector, func(t *testing.T) {
			// 解析向量
			p := NewCvss3xParser(v.vector)
			cvss3x, err := p.Parse()
			assert.NoError(t, err)

			// 创建计算器
			calculator := cvss.NewCalculator(cvss3x)

			// 计算评分
			score, err := calculator.Calculate()
			assert.NoError(t, err)

			// 验证评分是否符合预期
			// 注意：由于舍入的差异，这里使用近似比较
			assert.InDelta(t, v.expectedBase, score, 0.1)
		})
	}
}
