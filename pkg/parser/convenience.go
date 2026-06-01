package parser

import (
	"github.com/scagogogo/cvss-parser/pkg/cvss"
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
