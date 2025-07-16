# vector 包

`vector` 包定义了 CVSS 各种指标的接口和具体实现，提供了类型安全的指标表示和评分计算。

## 包概述

```go
import "github.com/scagogogo/cvss-parser/pkg/vector"
```

## 核心接口

### Vector 接口

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

## 指标分类

### 基础指标 (Base Metrics)
必需的8个指标，用于计算基础评分：

| 指标组 | 指标 | 文档链接 |
|--------|------|----------|
| 可利用性 | 攻击向量 (AV) | [详细文档](/api/vector/base-metrics#攻击向量) |
| 可利用性 | 攻击复杂性 (AC) | [详细文档](/api/vector/base-metrics#攻击复杂性) |
| 可利用性 | 所需权限 (PR) | [详细文档](/api/vector/base-metrics#所需权限) |
| 可利用性 | 用户交互 (UI) | [详细文档](/api/vector/base-metrics#用户交互) |
| 影响 | 影响范围 (S) | [详细文档](/api/vector/base-metrics#影响范围) |
| 影响 | 机密性影响 (C) | [详细文档](/api/vector/base-metrics#机密性影响) |
| 影响 | 完整性影响 (I) | [详细文档](/api/vector/base-metrics#完整性影响) |
| 影响 | 可用性影响 (A) | [详细文档](/api/vector/base-metrics#可用性影响) |

### 时间指标 (Temporal Metrics)
可选的3个指标，反映漏洞随时间变化的特征：

| 指标 | 简写 | 文档链接 |
|------|------|----------|
| 漏洞利用代码成熟度 | E | [详细文档](/api/vector/temporal-metrics#漏洞利用代码成熟度) |
| 修复级别 | RL | [详细文档](/api/vector/temporal-metrics#修复级别) |
| 报告可信度 | RC | [详细文档](/api/vector/temporal-metrics#报告可信度) |

### 环境指标 (Environmental Metrics)
可选的11个指标，允许根据特定环境调整评分：

| 指标类型 | 指标 | 简写 | 文档链接 |
|----------|------|------|----------|
| 安全需求 | 机密性需求 | CR | [详细文档](/api/vector/environmental-metrics#安全需求) |
| 安全需求 | 完整性需求 | IR | [详细文档](/api/vector/environmental-metrics#安全需求) |
| 安全需求 | 可用性需求 | AR | [详细文档](/api/vector/environmental-metrics#安全需求) |
| 修改的基础指标 | 修改的攻击向量 | MAV | [详细文档](/api/vector/environmental-metrics#修改的基础指标) |
| 修改的基础指标 | 修改的攻击复杂性 | MAC | [详细文档](/api/vector/environmental-metrics#修改的基础指标) |
| ... | ... | ... | ... |

## 快速示例

### 创建向量实例

```go
package main

import (
    "fmt"
    "github.com/scagogogo/cvss-parser/pkg/vector"
)

func main() {
    // 创建攻击向量实例
    av := &vector.AttackVectorNetwork{}
    
    fmt.Printf("指标组: %s\n", av.GetGroupName())      // "Exploitability"
    fmt.Printf("指标名: %s\n", av.GetShortName())      // "AV"
    fmt.Printf("指标值: %c\n", av.GetShortValue())     // 'N'
    fmt.Printf("评分: %.1f\n", av.GetScore())          // 0.85
    fmt.Printf("描述: %s\n", av.GetDescription())      // "Network"
}
```

### 使用工厂函数

```go
// 通过工厂函数创建向量
av, err := vector.NewAttackVector('N')
if err != nil {
    log.Fatalf("创建攻击向量失败: %v", err)
}

ac, err := vector.NewAttackComplexity('L')
if err != nil {
    log.Fatalf("创建攻击复杂性失败: %v", err)
}
```

### 向量比较

```go
func compareVectors() {
    av1 := &vector.AttackVectorNetwork{}
    av2 := &vector.AttackVectorLocal{}
    
    fmt.Printf("网络攻击向量评分: %.2f\n", av1.GetScore())  // 0.85
    fmt.Printf("本地攻击向量评分: %.2f\n", av2.GetScore())  // 0.55
    
    if av1.GetScore() > av2.GetScore() {
        fmt.Println("网络攻击向量风险更高")
    }
}
```

## 设计模式

### 1. 策略模式
每个指标值都是一个独立的策略实现：

```go
// 攻击向量的不同策略
type AttackVectorNetwork struct{}    // 网络攻击
type AttackVectorAdjacent struct{}   // 相邻网络攻击
type AttackVectorLocal struct{}      // 本地攻击
type AttackVectorPhysical struct{}   // 物理攻击
```

### 2. 工厂模式
提供工厂函数创建向量实例：

```go
func NewAttackVector(value rune) (Vector, error) {
    switch value {
    case 'N':
        return &AttackVectorNetwork{}, nil
    case 'A':
        return &AttackVectorAdjacent{}, nil
    case 'L':
        return &AttackVectorLocal{}, nil
    case 'P':
        return &AttackVectorPhysical{}, nil
    default:
        return nil, fmt.Errorf("unknown attack vector value: %c", value)
    }
}
```

### 3. 组合模式
CVSS 向量通过组合不同的指标构成：

```go
type Cvss3xBase struct {
    AttackVector       Vector
    AttackComplexity   Vector
    PrivilegesRequired Vector
    // ... 其他指标
}
```

## 指标评分规则

### 基础指标评分

#### 攻击向量 (AV)
- Network (N): 0.85
- Adjacent (A): 0.62
- Local (L): 0.55
- Physical (P): 0.20

#### 攻击复杂性 (AC)
- Low (L): 0.77
- High (H): 0.44

#### 所需权限 (PR)
- None (N): 0.85
- Low (L): 0.62 (范围不变) / 0.68 (范围改变)
- High (H): 0.27 (范围不变) / 0.50 (范围改变)

#### 用户交互 (UI)
- None (N): 0.85
- Required (R): 0.62

#### 影响范围 (S)
- Unchanged (U): 不直接参与评分计算
- Changed (C): 影响评分计算公式

#### CIA 影响 (C/I/A)
- None (N): 0.0
- Low (L): 0.22
- High (H): 0.56

### 时间指标评分

#### 漏洞利用代码成熟度 (E)
- Not Defined (X): 1.0
- Unproven (U): 0.91
- Proof-of-Concept (P): 0.94
- Functional (F): 0.97
- High (H): 1.0

#### 修复级别 (RL)
- Not Defined (X): 1.0
- Official Fix (O): 0.95
- Temporary Fix (T): 0.96
- Workaround (W): 0.97
- Unavailable (U): 1.0

#### 报告可信度 (RC)
- Not Defined (X): 1.0
- Unknown (U): 0.92
- Reasonable (R): 0.96
- Confirmed (C): 1.0

## 完整示例

### 创建完整的基础指标组

```go
package main

import (
    "fmt"
    "github.com/scagogogo/cvss-parser/pkg/vector"
    "github.com/scagogogo/cvss-parser/pkg/cvss"
)

func main() {
    // 创建 CVSS 向量
    cvssVector := cvss.NewCvss3x()
    cvssVector.MajorVersion = 3
    cvssVector.MinorVersion = 1
    
    // 设置基础指标
    cvssVector.Cvss3xBase.AttackVector = &vector.AttackVectorNetwork{}
    cvssVector.Cvss3xBase.AttackComplexity = &vector.AttackComplexityLow{}
    cvssVector.Cvss3xBase.PrivilegesRequired = &vector.PrivilegesRequiredNone{}
    cvssVector.Cvss3xBase.UserInteraction = &vector.UserInteractionNone{}
    cvssVector.Cvss3xBase.Scope = &vector.ScopeUnchanged{}
    cvssVector.Cvss3xBase.Confidentiality = &vector.ConfidentialityHigh{}
    cvssVector.Cvss3xBase.Integrity = &vector.IntegrityHigh{}
    cvssVector.Cvss3xBase.Availability = &vector.AvailabilityHigh{}
    
    // 验证向量
    if err := cvssVector.Check(); err != nil {
        fmt.Printf("向量验证失败: %v\n", err)
        return
    }
    
    // 输出向量信息
    fmt.Printf("CVSS 向量: %s\n", cvssVector.String())
    
    // 输出各指标详情
    fmt.Println("\n基础指标详情:")
    printVectorInfo("攻击向量", cvssVector.Cvss3xBase.AttackVector)
    printVectorInfo("攻击复杂性", cvssVector.Cvss3xBase.AttackComplexity)
    printVectorInfo("所需权限", cvssVector.Cvss3xBase.PrivilegesRequired)
    printVectorInfo("用户交互", cvssVector.Cvss3xBase.UserInteraction)
    printVectorInfo("影响范围", cvssVector.Cvss3xBase.Scope)
    printVectorInfo("机密性影响", cvssVector.Cvss3xBase.Confidentiality)
    printVectorInfo("完整性影响", cvssVector.Cvss3xBase.Integrity)
    printVectorInfo("可用性影响", cvssVector.Cvss3xBase.Availability)
}

func printVectorInfo(name string, v vector.Vector) {
    fmt.Printf("  %s (%s): %s (%.2f)\n", 
        name, v.GetShortName(), v.GetDescription(), v.GetScore())
}
```

### 使用工厂函数批量创建

```go
func createVectorsFromString(vectorStr string) error {
    // 解析向量字符串中的各个指标
    metrics := parseMetrics(vectorStr) // 假设的解析函数
    
    for key, value := range metrics {
        var v vector.Vector
        var err error
        
        switch key {
        case "AV":
            v, err = vector.NewAttackVector(rune(value[0]))
        case "AC":
            v, err = vector.NewAttackComplexity(rune(value[0]))
        case "PR":
            v, err = vector.NewPrivilegesRequired(rune(value[0]))
        // ... 其他指标
        }
        
        if err != nil {
            return fmt.Errorf("创建指标 %s 失败: %v", key, err)
        }
        
        fmt.Printf("%s: %s\n", key, v.GetDescription())
    }
    
    return nil
}
```

## 扩展性

### 自定义指标实现

```go
// 实现自定义指标
type CustomAttackVector struct {
    value       rune
    score       float64
    description string
}

func (c *CustomAttackVector) GetGroupName() string {
    return "Exploitability"
}

func (c *CustomAttackVector) GetShortName() string {
    return "AV"
}

func (c *CustomAttackVector) GetLongName() string {
    return "Attack Vector"
}

func (c *CustomAttackVector) GetShortValue() rune {
    return c.value
}

func (c *CustomAttackVector) GetLongValue() string {
    return c.description
}

func (c *CustomAttackVector) GetDescription() string {
    return c.description
}

func (c *CustomAttackVector) GetScore() float64 {
    return c.score
}

func (c *CustomAttackVector) String() string {
    return fmt.Sprintf("%s:%c", c.GetShortName(), c.GetShortValue())
}
```

## 最佳实践

### 1. 类型安全
```go
// 使用具体类型而不是接口
var av *vector.AttackVectorNetwork = &vector.AttackVectorNetwork{}
// 而不是
// var av vector.Vector = &vector.AttackVectorNetwork{}
```

### 2. 工厂函数
```go
// 推荐使用工厂函数
av, err := vector.NewAttackVector('N')
if err != nil {
    return err
}

// 而不是直接实例化
// av := &vector.AttackVectorNetwork{}
```

### 3. 错误处理
```go
func createVector(key string, value rune) (vector.Vector, error) {
    switch key {
    case "AV":
        return vector.NewAttackVector(value)
    case "AC":
        return vector.NewAttackComplexity(value)
    default:
        return nil, fmt.Errorf("unknown vector key: %s", key)
    }
}
```

## 包结构

```
vector/
├── vector.go                    # Vector 接口定义
├── vector_impl.go              # 通用实现
├── factory.go                  # 工厂函数
├── attack_vector.go            # 攻击向量实现
├── attack_complexity.go        # 攻击复杂性实现
├── privileges_required.go      # 所需权限实现
├── user_interaction.go         # 用户交互实现
├── scope.go                    # 影响范围实现
├── confidentiality.go          # 机密性影响实现
├── integrity.go                # 完整性影响实现
├── availability.go             # 可用性影响实现
├── exploit_code_maturity.go    # 漏洞利用代码成熟度实现
├── remediation_level.go        # 修复级别实现
├── report_confidence.go        # 报告可信度实现
├── confidentiality_requirement.go # 机密性需求实现
├── integrity_requirement.go    # 完整性需求实现
├── availability_requirement.go # 可用性需求实现
└── not_defined_vectors.go      # 未定义向量实现
```

## 下一步

深入了解具体的指标类型：

- 📖 [Vector 接口详解](/api/vector/interface)
- 🎯 [基础指标详解](/api/vector/base-metrics)
- ⏱️ [时间指标详解](/api/vector/temporal-metrics)
- 🌍 [环境指标详解](/api/vector/environmental-metrics)
