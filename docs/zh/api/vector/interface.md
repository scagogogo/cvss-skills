# Vector 接口

`Vector` 接口是 CVSS Skills 中所有指标的统一抽象，定义了指标的基本行为和属性。

## 接口定义

```go
type Vector interface {
    GetGroupName() string    // 获取指标组名称
    GetShortName() string    // 获取指标短名称
    GetLongName() string     // 获取指标完整名称
    GetShortValue() rune     // 获取指标短值
    GetLongValue() string    // 获取指标完整值
    GetDescription() string  // 获取指标描述
    GetScore() float64       // 获取指标分数
    String() string          // 字符串表示
}
```

## 方法详情

### GetGroupName

```go
GetGroupName() string
```

返回指标所属的组名称。

**返回值:**
- `string`: 指标组名称

**可能的值:**
- `"Base"` - 基础指标组
- `"Temporal"` - 时间指标组
- `"Environmental"` - 环境指标组

**示例:**
```go
av := &vector.AttackVectorNetwork{}
groupName := av.GetGroupName()
fmt.Printf("组: %s\n", groupName) // "Base"
```

### GetShortName

```go
GetShortName() string
```

返回指标的短名称（通常是缩写）。

**返回值:**
- `string`: 指标短名称

**示例:**
```go
av := &vector.AttackVectorNetwork{}
shortName := av.GetShortName()
fmt.Printf("短名称: %s\n", shortName) // "AV"
```

### GetLongName

```go
GetLongName() string
```

返回指标的完整名称。

**返回值:**
- `string`: 指标完整名称

**示例:**
```go
av := &vector.AttackVectorNetwork{}
longName := av.GetLongName()
fmt.Printf("完整名称: %s\n", longName) // "Attack Vector"
```

### GetShortValue

```go
GetShortValue() rune
```

返回指标值的短表示（单个字符）。

**返回值:**
- `rune`: 指标短值

**示例:**
```go
av := &vector.AttackVectorNetwork{}
shortValue := av.GetShortValue()
fmt.Printf("短值: %c\n", shortValue) // 'N'
```

### GetLongValue

```go
GetLongValue() string
```

返回指标值的完整描述。

**返回值:**
- `string`: 指标完整值

**示例:**
```go
av := &vector.AttackVectorNetwork{}
longValue := av.GetLongValue()
fmt.Printf("完整值: %s\n", longValue) // "Network"
```

### GetDescription

```go
GetDescription() string
```

返回指标的详细描述。

**返回值:**
- `string`: 指标描述

**示例:**
```go
av := &vector.AttackVectorNetwork{}
description := av.GetDescription()
fmt.Printf("描述: %s\n", description)
// "攻击者可以通过网络远程访问漏洞组件"
```

### GetScore

```go
GetScore() float64
```

返回指标在 CVSS 计算中的数值分数。

**返回值:**
- `float64`: 指标分数

**示例:**
```go
av := &vector.AttackVectorNetwork{}
score := av.GetScore()
fmt.Printf("分数: %.2f\n", score) // 0.85
```

### String

```go
String() string
```

返回指标的字符串表示，通常是短名称和短值的组合。

**返回值:**
- `string`: 字符串表示

**示例:**
```go
av := &vector.AttackVectorNetwork{}
str := av.String()
fmt.Printf("字符串: %s\n", str) // "AV:N"
```

## 指标分类

### 基础指标 (Base Metrics)

基础指标描述漏洞的固有特征，不随时间或环境变化。

#### 攻击向量 (Attack Vector - AV)
- **Network (N)**: 网络攻击 - 分数: 0.85
- **Adjacent (A)**: 相邻网络攻击 - 分数: 0.62
- **Local (L)**: 本地攻击 - 分数: 0.55
- **Physical (P)**: 物理攻击 - 分数: 0.20

#### 攻击复杂度 (Attack Complexity - AC)
- **Low (L)**: 低复杂度 - 分数: 0.77
- **High (H)**: 高复杂度 - 分数: 0.44

#### 所需权限 (Privileges Required - PR)
- **None (N)**: 无需权限 - 分数: 0.85
- **Low (L)**: 低权限 - 分数: 0.62/0.68 (取决于作用域)
- **High (H)**: 高权限 - 分数: 0.27/0.50 (取决于作用域)

#### 用户交互 (User Interaction - UI)
- **None (N)**: 无需交互 - 分数: 0.85
- **Required (R)**: 需要交互 - 分数: 0.62

#### 作用域 (Scope - S)
- **Unchanged (U)**: 作用域不变 - 分数: 1.0
- **Changed (C)**: 作用域改变 - 分数: 1.0

#### 影响指标 (Impact Metrics)
**机密性影响 (Confidentiality Impact - C)**
**完整性影响 (Integrity Impact - I)**
**可用性影响 (Availability Impact - A)**
- **None (N)**: 无影响 - 分数: 0.0
- **Low (L)**: 低影响 - 分数: 0.22
- **High (H)**: 高影响 - 分数: 0.56

### 时间指标 (Temporal Metrics)

时间指标反映随时间变化的漏洞特征。

#### 漏洞利用代码成熟度 (Exploit Code Maturity - E)
- **Not Defined (X)**: 未定义 - 分数: 1.0
- **Unproven (U)**: 未证实 - 分数: 0.91
- **Proof-of-Concept (P)**: 概念验证 - 分数: 0.94
- **Functional (F)**: 功能性 - 分数: 0.97
- **High (H)**: 高成熟度 - 分数: 1.0

#### 修复级别 (Remediation Level - RL)
- **Not Defined (X)**: 未定义 - 分数: 1.0
- **Official Fix (O)**: 官方修复 - 分数: 0.95
- **Temporary Fix (T)**: 临时修复 - 分数: 0.96
- **Workaround (W)**: 变通方法 - 分数: 0.97
- **Unavailable (U)**: 不可用 - 分数: 1.0

#### 报告可信度 (Report Confidence - RC)
- **Not Defined (X)**: 未定义 - 分数: 1.0
- **Unknown (U)**: 未知 - 分数: 0.92
- **Reasonable (R)**: 合理 - 分数: 0.96
- **Confirmed (C)**: 已确认 - 分数: 1.0

### 环境指标 (Environmental Metrics)

环境指标允许根据特定环境调整 CVSS 分数。

#### 安全需求 (Security Requirements)
**机密性需求 (Confidentiality Requirement - CR)**
**完整性需求 (Integrity Requirement - IR)**
**可用性需求 (Availability Requirement - AR)**
- **Not Defined (X)**: 未定义 - 分数: 1.0
- **Low (L)**: 低需求 - 分数: 0.5
- **Medium (M)**: 中等需求 - 分数: 1.0
- **High (H)**: 高需求 - 分数: 1.5

#### 修改的基础指标 (Modified Base Metrics)
所有基础指标都可以有对应的修改版本，前缀为 "M"：
- **MAV**: 修改的攻击向量
- **MAC**: 修改的攻击复杂度
- **MPR**: 修改的所需权限
- **MUI**: 修改的用户交互
- **MS**: 修改的作用域
- **MC**: 修改的机密性影响
- **MI**: 修改的完整性影响
- **MA**: 修改的可用性影响

## 实现示例

### 自定义指标实现

```go
type CustomMetric struct {
    groupName   string
    shortName   string
    longName    string
    shortValue  rune
    longValue   string
    description string
    score       float64
}

func (c *CustomMetric) GetGroupName() string {
    return c.groupName
}

func (c *CustomMetric) GetShortName() string {
    return c.shortName
}

func (c *CustomMetric) GetLongName() string {
    return c.longName
}

func (c *CustomMetric) GetShortValue() rune {
    return c.shortValue
}

func (c *CustomMetric) GetLongValue() string {
    return c.longValue
}

func (c *CustomMetric) GetDescription() string {
    return c.description
}

func (c *CustomMetric) GetScore() float64 {
    return c.score
}

func (c *CustomMetric) String() string {
    return fmt.Sprintf("%s:%c", c.shortName, c.shortValue)
}
```

### 指标工厂

```go
type MetricFactory struct {
    metrics map[string]map[rune]Vector
}

func NewMetricFactory() *MetricFactory {
    return &MetricFactory{
        metrics: make(map[string]map[rune]Vector),
    }
}

func (f *MetricFactory) RegisterMetric(shortName string, value rune, metric Vector) {
    if f.metrics[shortName] == nil {
        f.metrics[shortName] = make(map[rune]Vector)
    }
    f.metrics[shortName][value] = metric
}

func (f *MetricFactory) CreateMetric(shortName string, value rune) (Vector, error) {
    if metrics, exists := f.metrics[shortName]; exists {
        if metric, exists := metrics[value]; exists {
            return metric, nil
        }
    }
    return nil, fmt.Errorf("未知指标: %s:%c", shortName, value)
}
```

### 指标验证器

```go
type MetricValidator struct {
    validValues map[string][]rune
}

func NewMetricValidator() *MetricValidator {
    return &MetricValidator{
        validValues: map[string][]rune{
            "AV": {'N', 'A', 'L', 'P'},
            "AC": {'L', 'H'},
            "PR": {'N', 'L', 'H'},
            "UI": {'N', 'R'},
            "S":  {'U', 'C'},
            "C":  {'N', 'L', 'H'},
            "I":  {'N', 'L', 'H'},
            "A":  {'N', 'L', 'H'},
        },
    }
}

func (v *MetricValidator) ValidateMetric(metric Vector) error {
    shortName := metric.GetShortName()
    shortValue := metric.GetShortValue()

    if validValues, exists := v.validValues[shortName]; exists {
        for _, validValue := range validValues {
            if shortValue == validValue {
                return nil
            }
        }
        return fmt.Errorf("指标 %s 的值 %c 无效", shortName, shortValue)
    }

    return fmt.Errorf("未知指标: %s", shortName)
}
```

## 使用模式

### 指标遍历

```go
func printMetricInfo(metric Vector) {
    fmt.Printf("指标信息:\n")
    fmt.Printf("  组: %s\n", metric.GetGroupName())
    fmt.Printf("  短名称: %s\n", metric.GetShortName())
    fmt.Printf("  完整名称: %s\n", metric.GetLongName())
    fmt.Printf("  短值: %c\n", metric.GetShortValue())
    fmt.Printf("  完整值: %s\n", metric.GetLongValue())
    fmt.Printf("  描述: %s\n", metric.GetDescription())
    fmt.Printf("  分数: %.2f\n", metric.GetScore())
    fmt.Printf("  字符串: %s\n", metric.String())
}
```

### 指标比较

```go
func compareMetrics(m1, m2 Vector) {
    fmt.Printf("比较指标:\n")
    fmt.Printf("指标1: %s\n", m1.String())
    fmt.Printf("指标2: %s\n", m2.String())
    
    if m1.GetShortName() == m2.GetShortName() {
        fmt.Printf("相同指标类型: %s\n", m1.GetLongName())
        
        if m1.GetShortValue() == m2.GetShortValue() {
            fmt.Printf("相同值: %s\n", m1.GetLongValue())
        } else {
            fmt.Printf("不同值: %s vs %s\n", m1.GetLongValue(), m2.GetLongValue())
            scoreDiff := m1.GetScore() - m2.GetScore()
            fmt.Printf("分数差异: %.2f\n", scoreDiff)
        }
    } else {
        fmt.Printf("不同指标类型: %s vs %s\n", m1.GetLongName(), m2.GetLongName())
    }
}
```

## 最佳实践

### 指标处理

1. **类型安全**: 使用接口确保类型安全
2. **验证**: 始终验证指标值的有效性
3. **缓存**: 对频繁访问的指标进行缓存
4. **错误处理**: 妥善处理无效指标

### 性能优化

1. **预计算**: 预计算常用指标的分数
2. **池化**: 使用对象池减少内存分配
3. **批处理**: 批量处理多个指标

### 扩展性

1. **插件架构**: 支持自定义指标类型
2. **配置驱动**: 通过配置文件定义指标
3. **版本兼容**: 支持多个 CVSS 版本

## 相关文档

- [Vector 包概述](/zh/api/vector/) - Vector 包的完整文档
- [CVSS 数据结构](/zh/api/cvss/cvss3x) - 了解 CVSS 数据结构
- [解析器](/zh/api/parser/) - 了解如何解析指标
