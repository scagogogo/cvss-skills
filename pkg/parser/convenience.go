package parser

import (
	"fmt"
	"strings"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
)

// ParseString 解析 CVSS 3.x 向量字符串为 Cvss3x 对象
// 这是 NewCvss3xParser(str).Parse() 的一行简写
func ParseString(cvss3xStr string) (*cvss.Cvss3x, error) {
	return NewCvss3xParser(cvss3xStr).Parse()
}

// MustParse 解析 CVSS 3.x 向量字符串，如果解析失败则 panic
// 适用于初始化阶段确定向量字符串合法的场景
func MustParse(cvss3xStr string) *cvss.Cvss3x {
	result, err := NewCvss3xParser(cvss3xStr).Parse()
	if err != nil {
		panic(err)
	}
	return result
}

// ParseRelaxed 宽松解析 CVSS 向量字符串
// 与 ParseString 不同，ParseRelaxed 接受不带 "CVSS:3.1/" 前缀的向量字符串
// 例如 "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" 也能被正确解析
// 默认使用 CVSS v3.1，可通过 defaultVersion 参数指定版本（如 "3.0"）
func ParseRelaxed(cvss3xStr string, defaultVersion string) (*cvss.Cvss3x, error) {
	cvss3xStr = strings.TrimSpace(cvss3xStr)

	// 如果已经有前缀，直接用标准解析
	if strings.HasPrefix(strings.ToUpper(cvss3xStr), "CVSS:") {
		return ParseString(cvss3xStr)
	}

	// 没有前缀，自动添加
	if defaultVersion == "" {
		defaultVersion = "3.1"
	}
	prefixed := fmt.Sprintf("CVSS:%s/%s", defaultVersion, cvss3xStr)
	return ParseString(prefixed)
}

// ParseAndValidate 解析 CVSS 向量字符串并验证完整性
// 如果向量不完整（缺少必需指标），返回验证错误
// 等价于 ParseString + Validate，一步完成
func ParseAndValidate(cvss3xStr string) (*cvss.Cvss3x, error) {
	result, err := ParseString(cvss3xStr)
	if err != nil {
		return nil, err
	}
	if err := result.Validate(); err != nil {
		return nil, err
	}
	return result, nil
}

// ParseAndScore 解析 CVSS 向量字符串并计算评分
// 返回解析后的对象、基础评分和严重性等级
// 等价于 ParseString + NewCalculator + Calculate + GetSeverity，一步完成
//
// 用法:
//
//	cv, score, severity, err := parser.ParseAndScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("%.1f (%s)\n", score, severity)
func ParseAndScore(cvss3xStr string) (*cvss.Cvss3x, float64, cvss.Severity, error) {
	cv, err := ParseString(cvss3xStr)
	if err != nil {
		return nil, 0, cvss.SeverityNone, err
	}
	calc := cvss.NewCalculator(cv)
	score, err := calc.Calculate()
	if err != nil {
		return cv, 0, cvss.SeverityNone, err
	}
	return cv, score, cvss.GetSeverity(score), nil
}
