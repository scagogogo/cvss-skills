# Vector 接口

`Vector` 接口是 CVSS Parser 中所有指标的统一抽象，定义了指标的基本行为和属性。

## 接口定义

```go
type Vector interface {
    GetGroupName() string    // 获取指标组名称
    GetShortName() string    // 获取指标简称
    GetLongName() string     // 获取指标全称
    GetShortValue() rune     // 获取指标简写值
    GetLongValue() string    // 获取指标完整值
    GetDescription() string  // 获取指标描述
    GetScore() float64       // 获取指标评分
    String() string          // 字符串表示
}
```

## 方法详解

### GetGroupName

```go
GetGroupName() string
```

返回指标所属的组名称。

**返回值：**
- `"Exploitability"` - 可利用性指标组
- `"Impact"` - 影响指标组
- `"Temporal"` - 时间指标组
- `"Environmental"` - 环境指标组

**示例：**
```go
av := &vector.AttackVectorNetwork{}
fmt.Println(av.GetGroupName()) // "Exploitability"

c := &vector.ConfidentialityHigh{}
fmt.Println(c.GetGroupName()) // "Impact"
```

### GetShortName

```go
GetShortName() string
```

返回指标的简称，通常用于 CVSS 向量字符串中。

**示例：**
```go
av := &vector.AttackVectorNetwork{}
fmt.Println(av.GetShortName()) // "AV"

ac := &vector.AttackComplexityLow{}
fmt.Println(ac.GetShortName()) // "AC"
```

### GetLongName

```go
GetLongName() string
```

返回指标的完整名称。

**示例：**
```go
av := &vector.AttackVectorNetwork{}
fmt.Println(av.GetLongName()) // "Attack Vector"

pr := &vector.PrivilegesRequiredNone{}
fmt.Println(pr.GetLongName()) // "Privileges Required"
```

### GetShortValue

```go
GetShortValue() rune
```

返回指标值的简写字符，用于 CVSS 向量字符串中。

**示例：**
```go
av := &vector.AttackVectorNetwork{}
fmt.Printf("%c\n", av.GetShortValue()) // 'N'

ac := &vector.AttackComplexityHigh{}
fmt.Printf("%c\n", ac.GetShortValue()) // 'H'
```

### GetLongValue

```go
GetLongValue() string
```

返回指标值的完整描述。

**示例：**
```go
av := &vector.AttackVectorNetwork{}
fmt.Println(av.GetLongValue()) // "Network"

ui := &vector.UserInteractionRequired{}
fmt.Println(ui.GetLongValue()) // "Required"
```

### GetDescription

```go
GetDescription() string
```

返回指标的详细描述，通常与 `GetLongValue()` 相同。

**示例：**
```go
s := &vector.ScopeChanged{}
fmt.Println(s.GetDescription()) // "Changed"
```

### GetScore

```go
GetScore() float64
```

返回指标在 CVSS 评分计算中的数值。

**示例：**
```go
av := &vector.AttackVectorNetwork{}
fmt.Printf("%.2f\n", av.GetScore()) // 0.85

c := &vector.ConfidentialityHigh{}
fmt.Printf("%.2f\n", c.GetScore()) // 0.56
```

### String

```go
String() string
```

返回指标的字符串表示，格式为 "简称:简写值"。

**示例：**
```go
av := &vector.AttackVectorNetwork{}
fmt.Println(av.String()) // "AV:N"

ac := &vector.AttackComplexityLow{}
fmt.Println(ac.String()) // "AC:L"
```

## 实现示例

### 基本实现

```go
// 攻击向量 - 网络实现
type AttackVectorNetwork struct{}

func (a *AttackVectorNetwork) GetGroupName() string {
    return "Exploitability"
}

func (a *AttackVectorNetwork) GetShortName() string {
    return "AV"
}

func (a *AttackVectorNetwork) GetLongName() string {
    return "Attack Vector"
}

func (a *AttackVectorNetwork) GetShortValue() rune {
    return 'N'
}

func (a *AttackVectorNetwork) GetLongValue() string {
    return "Network"
}

func (a *AttackVectorNetwork) GetDescription() string {
    return "Network"
}

func (a *AttackVectorNetwork) GetScore() float64 {
    return 0.85
}

func (a *AttackVectorNetwork) String() string {
    return fmt.Sprintf("%s:%c", a.GetShortName(), a.GetShortValue())
}
```

### 通用实现基类

```go
// VectorImpl 提供 Vector 接口的通用实现
type VectorImpl struct {
    groupName   string
    shortName   string
    longName    string
    shortValue  rune
    longValue   string
    description string
    score       float64
}

func (v *VectorImpl) GetGroupName() string {
    return v.groupName
}

func (v *VectorImpl) GetShortName() string {
    return v.shortName
}

func (v *VectorImpl) GetLongName() string {
    return v.longName
}

func (v *VectorImpl) GetShortValue() rune {
    return v.shortValue
}

func (v *VectorImpl) GetLongValue() string {
    return v.longValue
}

func (v *VectorImpl) GetDescription() string {
    return v.description
}

func (v *VectorImpl) GetScore() float64 {
    return v.score
}

func (v *VectorImpl) String() string {
    return fmt.Sprintf("%s:%c", v.shortName, v.shortValue)
}
```

## 使用示例

### 基本使用

```go
package main

import (
    "fmt"
    "github.com/scagogogo/cvss-parser/pkg/vector"
)

func main() {
    // 创建向量实例
    vectors := []vector.Vector{
        &vector.AttackVectorNetwork{},
        &vector.AttackComplexityLow{},
        &vector.PrivilegesRequiredNone{},
        &vector.UserInteractionNone{},
        &vector.ScopeUnchanged{},
        &vector.ConfidentialityHigh{},
        &vector.IntegrityHigh{},
        &vector.AvailabilityHigh{},
    }
    
    // 输出向量信息
    for _, v := range vectors {
        printVectorInfo(v)
    }
}

func printVectorInfo(v vector.Vector) {
    fmt.Printf("指标: %s (%s)\n", v.GetLongName(), v.GetShortName())
    fmt.Printf("  组: %s\n", v.GetGroupName())
    fmt.Printf("  值: %s (%c)\n", v.GetLongValue(), v.GetShortValue())
    fmt.Printf("  评分: %.2f\n", v.GetScore())
    fmt.Printf("  字符串: %s\n", v.String())
    fmt.Println()
}
```

### 向量分组

```go
func groupVectorsByType(vectors []vector.Vector) map[string][]vector.Vector {
    groups := make(map[string][]vector.Vector)
    
    for _, v := range vectors {
        groupName := v.GetGroupName()
        groups[groupName] = append(groups[groupName], v)
    }
    
    return groups
}

func printGroupedVectors(vectors []vector.Vector) {
    groups := groupVectorsByType(vectors)
    
    for groupName, groupVectors := range groups {
        fmt.Printf("%s 指标组:\n", groupName)
        for _, v := range groupVectors {
            fmt.Printf("  %s: %s (%.2f)\n", 
                v.GetShortName(), v.GetDescription(), v.GetScore())
        }
        fmt.Println()
    }
}
```

### 向量比较

```go
func compareVectors(v1, v2 vector.Vector) {
    fmt.Printf("比较 %s 和 %s:\n", v1.String(), v2.String())
    
    if v1.GetShortName() != v2.GetShortName() {
        fmt.Println("  不同类型的指标，无法比较")
        return
    }
    
    score1 := v1.GetScore()
    score2 := v2.GetScore()
    
    if score1 > score2 {
        fmt.Printf("  %s (%.2f) > %s (%.2f)\n", 
            v1.GetDescription(), score1, v2.GetDescription(), score2)
    } else if score1 < score2 {
        fmt.Printf("  %s (%.2f) < %s (%.2f)\n", 
            v1.GetDescription(), score1, v2.GetDescription(), score2)
    } else {
        fmt.Printf("  %s = %s (%.2f)\n", 
            v1.GetDescription(), v2.GetDescription(), score1)
    }
}
```

### 向量验证

```go
func validateVector(v vector.Vector) error {
    // 检查基本属性
    if v.GetShortName() == "" {
        return fmt.Errorf("指标简称不能为空")
    }
    
    if v.GetLongName() == "" {
        return fmt.Errorf("指标全称不能为空")
    }
    
    if v.GetShortValue() == 0 {
        return fmt.Errorf("指标简写值不能为空")
    }
    
    if v.GetScore() < 0 || v.GetScore() > 1 {
        return fmt.Errorf("指标评分必须在 0-1 之间，当前值: %.2f", v.GetScore())
    }
    
    return nil
}

func validateVectors(vectors []vector.Vector) []error {
    var errors []error
    
    for i, v := range vectors {
        if err := validateVector(v); err != nil {
            errors = append(errors, fmt.Errorf("向量 %d 验证失败: %w", i, err))
        }
    }
    
    return errors
}
```

## 工厂模式

### 向量工厂

```go
type VectorFactory struct{}

func (f *VectorFactory) CreateAttackVector(value rune) (vector.Vector, error) {
    switch value {
    case 'N':
        return &vector.AttackVectorNetwork{}, nil
    case 'A':
        return &vector.AttackVectorAdjacent{}, nil
    case 'L':
        return &vector.AttackVectorLocal{}, nil
    case 'P':
        return &vector.AttackVectorPhysical{}, nil
    default:
        return nil, fmt.Errorf("未知的攻击向量值: %c", value)
    }
}

func (f *VectorFactory) CreateVector(shortName string, value rune) (vector.Vector, error) {
    switch shortName {
    case "AV":
        return f.CreateAttackVector(value)
    case "AC":
        return f.CreateAttackComplexity(value)
    // ... 其他指标
    default:
        return nil, fmt.Errorf("未知的指标类型: %s", shortName)
    }
}
```

### 批量创建

```go
func createVectorsFromMap(vectorMap map[string]rune) ([]vector.Vector, error) {
    factory := &VectorFactory{}
    var vectors []vector.Vector
    
    for shortName, value := range vectorMap {
        v, err := factory.CreateVector(shortName, value)
        if err != nil {
            return nil, fmt.Errorf("创建向量 %s:%c 失败: %w", shortName, value, err)
        }
        vectors = append(vectors, v)
    }
    
    return vectors, nil
}
```

## 扩展接口

### 可序列化向量

```go
type SerializableVector interface {
    Vector
    MarshalJSON() ([]byte, error)
    UnmarshalJSON([]byte) error
}
```

### 可验证向量

```go
type ValidatableVector interface {
    Vector
    Validate() error
}
```

### 可比较向量

```go
type ComparableVector interface {
    Vector
    Compare(Vector) int  // -1: 小于, 0: 等于, 1: 大于
}
```

## 最佳实践

### 1. 类型断言

```go
func getAttackVectorScore(v vector.Vector) (float64, error) {
    if v.GetShortName() != "AV" {
        return 0, fmt.Errorf("不是攻击向量指标")
    }
    return v.GetScore(), nil
}
```

### 2. 接口组合

```go
type CVSSVector interface {
    vector.Vector
    IsRequired() bool
    GetCategory() string
}
```

### 3. 空值处理

```go
func safeGetScore(v vector.Vector) float64 {
    if v == nil {
        return 0.0
    }
    return v.GetScore()
}
```

## 相关文档

- [基础指标](/api/vector/base-metrics)
- [时间指标](/api/vector/temporal-metrics)
- [环境指标](/api/vector/environmental-metrics)
- [vector 包概述](/api/vector/)
