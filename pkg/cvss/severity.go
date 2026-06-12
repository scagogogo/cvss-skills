package cvss

import (
	"fmt"
)

// Severity 表示 CVSS 严重性等级
type Severity string

const (
	// SeverityNone 无影响
	SeverityNone Severity = "None"
	// SeverityLow 低危
	SeverityLow Severity = "Low"
	// SeverityMedium 中危
	SeverityMedium Severity = "Medium"
	// SeverityHigh 高危
	SeverityHigh Severity = "High"
	// SeverityCritical 严重
	SeverityCritical Severity = "Critical"
)

// GetSeverity 根据 CVSS 分数返回严重性等级
// 这是 Calculator.GetSeverityRating 的独立版本，无需创建 Calculator 实例
// 按照 CVSS v3.1 规范的阈值: None=0, Low=0.1-3.9, Medium=4.0-6.9, High=7.0-8.9, Critical=9.0-10.0
func GetSeverity(score float64) Severity {
	if score <= 0 {
		return SeverityNone
	} else if score < 4.0 {
		return SeverityLow
	} else if score < 7.0 {
		return SeverityMedium
	} else if score < 9.0 {
		return SeverityHigh
	} else {
		return SeverityCritical
	}
}

// ParseSeverity 将字符串解析为 Severity 类型
// 支持的值: None, Low, Medium, High, Critical（不区分大小写）
func ParseSeverity(s string) (Severity, error) {
	switch Severity(s) {
	case SeverityNone, "none", "NONE":
		return SeverityNone, nil
	case SeverityLow, "low", "LOW":
		return SeverityLow, nil
	case SeverityMedium, "medium", "MEDIUM":
		return SeverityMedium, nil
	case SeverityHigh, "high", "HIGH":
		return SeverityHigh, nil
	case SeverityCritical, "critical", "CRITICAL":
		return SeverityCritical, nil
	default:
		return "", fmt.Errorf("invalid severity: %s (must be None, Low, Medium, High, or Critical)", s)
	}
}

// String 返回严重性等级的字符串表示
func (s Severity) String() string {
	return string(s)
}

// IsNone 判断是否为 None 等级
func (s Severity) IsNone() bool {
	return s == SeverityNone
}

// IsLow 判断是否为 Low 等级
func (s Severity) IsLow() bool {
	return s == SeverityLow
}

// IsMedium 判断是否为 Medium 等级
func (s Severity) IsMedium() bool {
	return s == SeverityMedium
}

// IsHigh 判断是否为 High 等级
func (s Severity) IsHigh() bool {
	return s == SeverityHigh
}

// IsCritical 判断是否为 Critical 等级
func (s Severity) IsCritical() bool {
	return s == SeverityCritical
}
