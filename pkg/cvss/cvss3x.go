package cvss

import (
	"fmt"
	"strings"
)

// Cvss3x 表示一个3.x的编号
// CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H
type Cvss3x struct {
	*Cvss3xBase
	*Cvss3xTemporal
	*Cvss3xEnvironmental

	// 主版本号
	MajorVersion int

	// 次版本号
	MinorVersion int
}

func NewCvss3x() *Cvss3x {
	return &Cvss3x{
		Cvss3xBase:          &Cvss3xBase{},
		Cvss3xTemporal:      nil,
		Cvss3xEnvironmental: nil,
	}
}

// Check 检查CVSS编号是否合法，包括版本号、基础指标、时间指标和环境指标
func (x *Cvss3x) Check() error {
	// 校验版本号
	if x.MajorVersion != 3 {
		return fmt.Errorf("unsupported CVSS major version: %d, only version 3 is supported", x.MajorVersion)
	}
	if x.MinorVersion != 0 && x.MinorVersion != 1 {
		return fmt.Errorf("unsupported CVSS minor version: %d, only 3.0 and 3.1 are supported", x.MinorVersion)
	}

	// 校验基础指标（必须存在且完整）
	if x.Cvss3xBase == nil {
		return fmt.Errorf("cvss3x base is nil")
	}
	if err := x.Cvss3xBase.Check(); err != nil {
		return err
	}

	// 校验时间指标（可选，但如果存在则已设置的字段必须合法）
	if x.Cvss3xTemporal != nil {
		if err := x.Cvss3xTemporal.Check(); err != nil {
			return err
		}
	}

	// 校验环境指标（可选，但如果存在则已设置的字段必须合法）
	if x.Cvss3xEnvironmental != nil {
		if err := x.Cvss3xEnvironmental.Check(); err != nil {
			return err
		}
	}

	return nil
}

func (x *Cvss3x) String() string {
	buff := strings.Builder{}
	buff.WriteString(fmt.Sprintf("CVSS:%d.%d", x.MajorVersion, x.MinorVersion))

	if x.Cvss3xBase != nil {
		s := x.Cvss3xBase.String()
		if s != "" {
			buff.WriteString("/")
			buff.WriteString(s)
		}
	}

	if x.Cvss3xTemporal != nil {
		s := x.Cvss3xTemporal.String()
		if s != "" {
			buff.WriteString("/")
			buff.WriteString(s)
		}
	}

	if x.Cvss3xEnvironmental != nil {
		s := x.Cvss3xEnvironmental.String()
		if s != "" {
			buff.WriteString("/")
			buff.WriteString(s)
		}
	}

	return buff.String()
}

// MarshalJSON 实现 json.Marshaler 接口
// 将 Cvss3x 序列化为向量字符串格式
func (x *Cvss3x) MarshalJSON() ([]byte, error) {
	if x == nil {
		return []byte("null"), nil
	}
	// 使用向量字符串作为 JSON 表示
	return []byte(`"` + x.String() + `"`), nil
}

// UnmarshalJSON 实现 json.Unmarshaler 接口
// 从向量字符串反序列化为 Cvss3x
func (x *Cvss3x) UnmarshalJSON(data []byte) error {
	s := string(data)
	if s == "null" || s == `""` {
		return nil
	}
	// 去掉引号
	s = strings.Trim(s, `"`)
	parsed, err := fromVectorString(s)
	if err != nil {
		return fmt.Errorf("failed to unmarshal Cvss3x: %w", err)
	}
	*x = *parsed
	return nil
}
