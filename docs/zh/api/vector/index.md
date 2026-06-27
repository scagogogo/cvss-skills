# vector 包

`vector` 包提供了 CVSS 指标的统一接口和具体实现。它定义了所有 CVSS 3.x 指标的行为和属性，为解析器和计算器提供了基础的数据结构。

## 包概述

```go
import "github.com/scagogogo/cvss-skills/pkg/vector"
```

## 核心接口

### Vector 接口

所有 CVSS 指标都实现了 `Vector` 接口：

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

详细文档：[Vector 接口](/zh/api/vector/interface)

## 指标分类

### 基础指标 (Base Metrics)

基础指标描述了漏洞的固有特征，不随时间或环境变化。

#### 可利用性指标

| 指标 | 简称 | 实现类型 | 可能值 |
|------|------|----------|--------|
| 攻击向量 | AV | `AttackVector*` | Network, Adjacent, Local, Physical |
| 攻击复杂性 | AC | `AttackComplexity*` | Low, High |
| 所需权限 | PR | `PrivilegesRequired*` | None, Low, High |
| 用户交互 | UI | `UserInteraction*` | None, Required |

#### 影响指标

| 指标 | 简称 | 实现类型 | 可能值 |
|------|------|----------|--------|
| 范围 | S | `Scope*` | Unchanged, Changed |
| 机密性影响 | C | `Confidentiality*` | None, Low, High |
| 完整性影响 | I | `Integrity*` | None, Low, High |
| 可用性影响 | A | `Availability*` | None, Low, High |

### 时间指标 (Temporal Metrics)

时间指标反映了漏洞随时间变化的特征。

| 指标 | 简称 | 实现类型 | 可能值 |
|------|------|----------|--------|
| 利用代码成熟度 | E | `ExploitCodeMaturity*` | Not Defined, Unproven, Proof-of-Concept, Functional, High |
| 修复级别 | RL | `RemediationLevel*` | Not Defined, Official Fix, Temporary Fix, Workaround, Unavailable |
| 报告置信度 | RC | `ReportConfidence*` | Not Defined, Unknown, Reasonable, Confirmed |

### 环境指标 (Environmental Metrics)

环境指标允许根据特定环境自定义评分。

#### 环境需求指标

| 指标 | 简称 | 实现类型 | 可能值 |
|------|------|----------|--------|
| 机密性需求 | CR | `ConfidentialityRequirement*` | Not Defined, Low, Medium, High |
| 完整性需求 | IR | `IntegrityRequirement*` | Not Defined, Low, Medium, High |
| 可用性需求 | AR | `AvailabilityRequirement*` | Not Defined, Low, Medium, High |

#### 修改后的基础指标

所有基础指标都有对应的修改版本，前缀为 `Modified`：

- `ModifiedAttackVector*`
- `ModifiedAttackComplexity*`
- `ModifiedPrivilegesRequired*`
- 等等...

## 使用示例

### 创建指标实例

```go
// 创建攻击向量指标
attackVector := &vector.AttackVectorNetwork{}
fmt.Printf("攻击向量: %s (%s)\n", 
    attackVector.GetLongValue(), 
    attackVector.GetDescription())

// 创建攻击复杂性指标
attackComplexity := &vector.AttackComplexityLow{}
fmt.Printf("攻击复杂性: %s (评分: %.2f)\n", 
    attackComplexity.GetLongValue(), 
    attackComplexity.GetScore())
```

### 使用接口

```go
func printVectorInfo(v vector.Vector) {
    fmt.Printf("指标: %s (%s)\n", v.GetLongName(), v.GetShortName())
    fmt.Printf("  组: %s\n", v.GetGroupName())
    fmt.Printf("  值: %s (%c)\n", v.GetLongValue(), v.GetShortValue())
    fmt.Printf("  评分: %.2f\n", v.GetScore())
    fmt.Printf("  字符串: %s\n", v.String())
}

// 使用示例
av := &vector.AttackVectorNetwork{}
printVectorInfo(av)
```

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
```

## 指标详细信息

### 攻击向量 (Attack Vector)

描述攻击者如何访问漏洞组件。

```go
// 网络攻击向量
type AttackVectorNetwork struct{}
func (a *AttackVectorNetwork) GetShortValue() rune { return 'N' }
func (a *AttackVectorNetwork) GetScore() float64 { return 0.85 }

// 相邻网络攻击向量
type AttackVectorAdjacent struct{}
func (a *AttackVectorAdjacent) GetShortValue() rune { return 'A' }
func (a *AttackVectorAdjacent) GetScore() float64 { return 0.62 }

// 本地攻击向量
type AttackVectorLocal struct{}
func (a *AttackVectorLocal) GetShortValue() rune { return 'L' }
func (a *AttackVectorLocal) GetScore() float64 { return 0.55 }

// 物理攻击向量
type AttackVectorPhysical struct{}
func (a *AttackVectorPhysical) GetShortValue() rune { return 'P' }
func (a *AttackVectorPhysical) GetScore() float64 { return 0.2 }
```

### 攻击复杂性 (Attack Complexity)

描述攻击成功所需的条件。

```go
// 低复杂性
type AttackComplexityLow struct{}
func (a *AttackComplexityLow) GetShortValue() rune { return 'L' }
func (a *AttackComplexityLow) GetScore() float64 { return 0.77 }

// 高复杂性
type AttackComplexityHigh struct{}
func (a *AttackComplexityHigh) GetShortValue() rune { return 'H' }
func (a *AttackComplexityHigh) GetScore() float64 { return 0.44 }
```

### 影响指标

影响指标描述了成功攻击对系统的影响程度。

```go
// 机密性影响
type ConfidentialityHigh struct{}
func (c *ConfidentialityHigh) GetShortValue() rune { return 'H' }
func (c *ConfidentialityHigh) GetScore() float64 { return 0.56 }

type ConfidentialityLow struct{}
func (c *ConfidentialityLow) GetShortValue() rune { return 'L' }
func (c *ConfidentialityLow) GetScore() float64 { return 0.22 }

type ConfidentialityNone struct{}
func (c *ConfidentialityNone) GetShortValue() rune { return 'N' }
func (c *ConfidentialityNone) GetScore() float64 { return 0.0 }
```

## 向量验证

### 基本验证

```go
func validateVector(v vector.Vector) error {
    if v.GetShortName() == "" {
        return fmt.Errorf("指标简称不能为空")
    }
    
    if v.GetShortValue() == 0 {
        return fmt.Errorf("指标值不能为空")
    }
    
    score := v.GetScore()
    if score < 0 || score > 1 {
        return fmt.Errorf("指标评分必须在 0-1 之间，当前值: %.2f", score)
    }
    
    return nil
}
```

### 批量验证

```go
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

## 向量比较

### 基本比较

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
```

## 扩展和自定义

### 自定义向量

```go
// 自定义向量实现
type CustomVector struct {
    groupName   string
    shortName   string
    longName    string
    shortValue  rune
    longValue   string
    description string
    score       float64
}

func (c *CustomVector) GetGroupName() string { return c.groupName }
func (c *CustomVector) GetShortName() string { return c.shortName }
func (c *CustomVector) GetLongName() string { return c.longName }
func (c *CustomVector) GetShortValue() rune { return c.shortValue }
func (c *CustomVector) GetLongValue() string { return c.longValue }
func (c *CustomVector) GetDescription() string { return c.description }
func (c *CustomVector) GetScore() float64 { return c.score }
func (c *CustomVector) String() string {
    return fmt.Sprintf("%s:%c", c.shortName, c.shortValue)
}
```

### 向量注册表

```go
type VectorRegistry struct {
    vectors map[string]map[rune]vector.Vector
}

func NewVectorRegistry() *VectorRegistry {
    return &VectorRegistry{
        vectors: make(map[string]map[rune]vector.Vector),
    }
}

func (r *VectorRegistry) Register(shortName string, value rune, v vector.Vector) {
    if r.vectors[shortName] == nil {
        r.vectors[shortName] = make(map[rune]vector.Vector)
    }
    r.vectors[shortName][value] = v
}

func (r *VectorRegistry) Get(shortName string, value rune) (vector.Vector, bool) {
    if group, exists := r.vectors[shortName]; exists {
        if v, found := group[value]; found {
            return v, true
        }
    }
    return nil, false
}
```

## 性能优化

### 向量缓存

```go
var vectorCache = make(map[string]vector.Vector)
var cacheMutex sync.RWMutex

func getCachedVector(key string) (vector.Vector, bool) {
    cacheMutex.RLock()
    defer cacheMutex.RUnlock()
    
    v, exists := vectorCache[key]
    return v, exists
}

func setCachedVector(key string, v vector.Vector) {
    cacheMutex.Lock()
    defer cacheMutex.Unlock()
    
    vectorCache[key] = v
}
```

### 对象池

```go
var vectorPool = sync.Pool{
    New: func() interface{} {
        return &vector.AttackVectorNetwork{}
    },
}

func getVectorFromPool() vector.Vector {
    return vectorPool.Get().(vector.Vector)
}

func putVectorToPool(v vector.Vector) {
    vectorPool.Put(v)
}
```

## 最佳实践

### 1. 类型安全

```go
func getAttackVectorScore(v vector.Vector) (float64, error) {
    if v.GetShortName() != "AV" {
        return 0, fmt.Errorf("不是攻击向量指标")
    }
    return v.GetScore(), nil
}
```

### 2. 空值处理

```go
func safeGetScore(v vector.Vector) float64 {
    if v == nil {
        return 0.0
    }
    return v.GetScore()
}
```

### 3. 接口组合

```go
type CVSSVector interface {
    vector.Vector
    IsRequired() bool
    GetCategory() string
}
```

## 相关文档

- [Vector 接口详解](/zh/api/vector/interface)
- [Cvss3x 数据结构](/zh/api/cvss/cvss3x)
- [Parser 解析器](/zh/api/parser/cvss3x-parser)
- [使用示例](/zh/examples/basic)
