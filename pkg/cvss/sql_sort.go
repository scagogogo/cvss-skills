package cvss

import (
	"database/sql/driver"
	"fmt"
	"sort"
	"strings"
)

// Scan 实现 sql.Scanner 接口
// 支持从数据库读取 CVSS 向量字符串
// 可用于 database/sql 驱动（如 MySQL, PostgreSQL, SQLite 等）
//
// 用法:
//
//	var cv cvss.Cvss3x
//	rows.Scan(&cv)  // 自动从 VARCHAR/TEXT 列读取
func (x *Cvss3x) Scan(src interface{}) error {
	if src == nil {
		*x = Cvss3x{Cvss3xBase: &Cvss3xBase{}}
		return nil
	}

	var str string
	switch v := src.(type) {
	case string:
		str = v
	case []byte:
		str = string(v)
	default:
		return fmt.Errorf("cannot scan %T into Cvss3x", src)
	}

	if str == "" {
		*x = Cvss3x{Cvss3xBase: &Cvss3xBase{}}
		return nil
	}

	parsed, err := fromVectorString(str)
	if err != nil {
		return fmt.Errorf("failed to scan Cvss3x: %w", err)
	}

	*x = *parsed
	return nil
}

// Value 实现 driver.Valuer 接口
// 支持将 CVSS 向量写入数据库
// 返回向量字符串格式，适合存储在 VARCHAR/TEXT 列
//
// 用法:
//
//	cv := cvss.CriticalV31()
//	result, err := db.Exec("INSERT INTO vulns (cvss) VALUES (?)", cv)
func (x *Cvss3x) Value() (driver.Value, error) {
	if x == nil {
		return nil, nil
	}
	return x.String(), nil
}

// Cvss3xSlice 实现 sort.Interface 的 Cvss3x 切片
// 支持按评分排序
type Cvss3xSlice struct {
	items  []*Cvss3x
	scores []float64
	desc   bool // 是否降序
}

// NewCvss3xSlice 创建一个可排序的 Cvss3x 切片
// 默认按评分降序排列（Critical 在前）
//
// 用法:
//
//	slice := cvss.NewCvss3xSlice(v1, v2, v3)
//	sort.Sort(slice)
//	for _, cv := range slice.Items() {
//	    fmt.Println(cv.String())
//	}
func NewCvss3xSlice(items ...*Cvss3x) *Cvss3xSlice {
	s := &Cvss3xSlice{
		items:  items,
		scores: make([]float64, len(items)),
		desc:   true,
	}
	for i, cv := range items {
		if cv != nil {
			calc := NewCalculator(cv)
			score, err := calc.Calculate()
			if err != nil {
				s.scores[i] = -1 // 无效向量排最后
			} else {
				s.scores[i] = score
			}
		}
	}
	return s
}

// Len 实现 sort.Interface
func (s *Cvss3xSlice) Len() int {
	return len(s.items)
}

// Less 实现 sort.Interface
func (s *Cvss3xSlice) Less(i, j int) bool {
	if s.desc {
		return s.scores[i] > s.scores[j]
	}
	return s.scores[i] < s.scores[j]
}

// Swap 实现 sort.Interface
func (s *Cvss3xSlice) Swap(i, j int) {
	s.items[i], s.items[j] = s.items[j], s.items[i]
	s.scores[i], s.scores[j] = s.scores[j], s.scores[i]
}

// Items 返回排序后的 Cvss3x 切片
func (s *Cvss3xSlice) Items() []*Cvss3x {
	return s.items
}

// Asc 设置升序排列
func (s *Cvss3xSlice) Asc() *Cvss3xSlice {
	s.desc = false
	return s
}

// Desc 设置降序排列（默认）
func (s *Cvss3xSlice) Desc() *Cvss3xSlice {
	s.desc = true
	return s
}

// Sort 执行排序并返回自身
func (s *Cvss3xSlice) Sort() *Cvss3xSlice {
	sort.Sort(s)
	return s
}

// ScoreAt 返回指定索引的评分
func (s *Cvss3xSlice) ScoreAt(i int) float64 {
	if i < 0 || i >= len(s.scores) {
		return 0
	}
	return s.scores[i]
}

// Canonicalize 将向量字符串规范化
// 按照 CVSS 规范的指标顺序输出，去除多余的空格
// 注意：此方法不修改原对象，返回规范化后的向量字符串
//
// CVSS 规范的指标顺序：
// Base: AV, AC, PR, UI, S, C, I, A
// Temporal: E, RL, RC
// Environmental: CR, IR, AR, MAV, MAC, MPR, MUI, MS, MC, MI, MA
//
// 用法:
//
//	normalized := cvss.Canonicalize("CVSS:3.1/S:U/C:H/I:H/A:H/AV:N/AC:L/PR:N/UI:N")
//	// 输出: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
func Canonicalize(vectorString string) (string, error) {
	cv, err := fromVectorString(strings.TrimSpace(vectorString))
	if err != nil {
		return "", fmt.Errorf("cannot canonicalize: %w", err)
	}
	return cv.String(), nil
}

// CanonicalizeString 将 Cvss3x 的字符串规范化
// 等价于 cv.String()，因为 String() 已按规范顺序输出
func (x *Cvss3x) CanonicalizeString() string {
	if x == nil {
		return ""
	}
	return x.String()
}

// IsCanonical 检查向量字符串是否已经是规范顺序
func IsCanonical(vectorString string) bool {
	canonical, err := Canonicalize(vectorString)
	if err != nil {
		return false
	}
	return vectorString == canonical
}
