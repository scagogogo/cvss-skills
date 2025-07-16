# Cvss3x 数据结构

`Cvss3x` 是 CVSS Parser 中表示 CVSS 3.x 向量的核心数据结构。它包含了完整的 CVSS 向量信息，包括版本、基础指标、时间指标和环境指标。

## 结构定义

```go
type Cvss3x struct {
    MajorVersion         int                   `json:"major_version"`
    MinorVersion         int                   `json:"minor_version"`
    Cvss3xBase          *Cvss3xBase           `json:"base_metrics"`
    Cvss3xTemporal      *Cvss3xTemporal       `json:"temporal_metrics,omitempty"`
    Cvss3xEnvironmental *Cvss3xEnvironmental  `json:"environmental_metrics,omitempty"`
}
```

## 字段说明

### 版本信息

| 字段 | 类型 | 描述 | 示例 |
|------|------|------|------|
| `MajorVersion` | `int` | CVSS 主版本号 | `3` |
| `MinorVersion` | `int` | CVSS 次版本号 | `1` |

### 指标组

| 字段 | 类型 | 描述 | 必需 |
|------|------|------|------|
| `Cvss3xBase` | `*Cvss3xBase` | 基础指标组 | ✅ |
| `Cvss3xTemporal` | `*Cvss3xTemporal` | 时间指标组 | ❌ |
| `Cvss3xEnvironmental` | `*Cvss3xEnvironmental` | 环境指标组 | ❌ |

## 基础指标组 (Cvss3xBase)

基础指标组包含了描述漏洞固有特征的指标，这些指标在时间和环境变化时保持不变。

```go
type Cvss3xBase struct {
    AttackVector        Vector `json:"attack_vector"`
    AttackComplexity    Vector `json:"attack_complexity"`
    PrivilegesRequired  Vector `json:"privileges_required"`
    UserInteraction     Vector `json:"user_interaction"`
    Scope              Vector `json:"scope"`
    Confidentiality    Vector `json:"confidentiality"`
    Integrity          Vector `json:"integrity"`
    Availability       Vector `json:"availability"`
}
```

### 可利用性指标

| 指标 | 简称 | 描述 | 可能值 |
|------|------|------|--------|
| 攻击向量 | AV | 攻击者访问漏洞的方式 | Network(N), Adjacent(A), Local(L), Physical(P) |
| 攻击复杂性 | AC | 攻击的复杂程度 | Low(L), High(H) |
| 所需权限 | PR | 攻击前需要的权限级别 | None(N), Low(L), High(H) |
| 用户交互 | UI | 是否需要用户参与 | None(N), Required(R) |

### 影响指标

| 指标 | 简称 | 描述 | 可能值 |
|------|------|------|--------|
| 范围 | S | 漏洞是否影响其他组件 | Unchanged(U), Changed(C) |
| 机密性影响 | C | 对信息机密性的影响 | None(N), Low(L), High(H) |
| 完整性影响 | I | 对信息完整性的影响 | None(N), Low(L), High(H) |
| 可用性影响 | A | 对系统可用性的影响 | None(N), Low(L), High(H) |

## 时间指标组 (Cvss3xTemporal)

时间指标组反映了漏洞随时间变化的特征。

```go
type Cvss3xTemporal struct {
    ExploitCodeMaturity Vector `json:"exploit_code_maturity,omitempty"`
    RemediationLevel    Vector `json:"remediation_level,omitempty"`
    ReportConfidence    Vector `json:"report_confidence,omitempty"`
}
```

| 指标 | 简称 | 描述 | 可能值 |
|------|------|------|--------|
| 利用代码成熟度 | E | 可用利用代码的成熟程度 | Not Defined(X), Unproven(U), Proof-of-Concept(P), Functional(F), High(H) |
| 修复级别 | RL | 可用修复措施的级别 | Not Defined(X), Official Fix(O), Temporary Fix(T), Workaround(W), Unavailable(U) |
| 报告置信度 | RC | 漏洞报告的置信程度 | Not Defined(X), Unknown(U), Reasonable(R), Confirmed(C) |

## 环境指标组 (Cvss3xEnvironmental)

环境指标组允许分析师根据特定环境自定义 CVSS 评分。

```go
type Cvss3xEnvironmental struct {
    // 环境需求指标
    ConfidentialityRequirement Vector `json:"confidentiality_requirement,omitempty"`
    IntegrityRequirement       Vector `json:"integrity_requirement,omitempty"`
    AvailabilityRequirement    Vector `json:"availability_requirement,omitempty"`
    
    // 修改后的基础指标
    ModifiedAttackVector       Vector `json:"modified_attack_vector,omitempty"`
    ModifiedAttackComplexity   Vector `json:"modified_attack_complexity,omitempty"`
    ModifiedPrivilegesRequired Vector `json:"modified_privileges_required,omitempty"`
    ModifiedUserInteraction    Vector `json:"modified_user_interaction,omitempty"`
    ModifiedScope             Vector `json:"modified_scope,omitempty"`
    ModifiedConfidentiality   Vector `json:"modified_confidentiality,omitempty"`
    ModifiedIntegrity         Vector `json:"modified_integrity,omitempty"`
    ModifiedAvailability      Vector `json:"modified_availability,omitempty"`
}
```

### 环境需求指标

| 指标 | 简称 | 描述 | 可能值 |
|------|------|------|--------|
| 机密性需求 | CR | 受影响系统机密性的重要程度 | Not Defined(X), Low(L), Medium(M), High(H) |
| 完整性需求 | IR | 受影响系统完整性的重要程度 | Not Defined(X), Low(L), Medium(M), High(H) |
| 可用性需求 | AR | 受影响系统可用性的重要程度 | Not Defined(X), Low(L), Medium(M), High(H) |

### 修改后的基础指标

修改后的基础指标允许分析师根据特定环境调整基础指标值。如果未指定，则使用原始基础指标值。

## 主要方法

### String

```go
func (c *Cvss3x) String() string
```

将 CVSS 向量转换为标准的字符串表示形式。

**示例：**
```go
vector := &cvss.Cvss3x{
    MajorVersion: 3,
    MinorVersion: 1,
    // ... 设置指标
}

vectorString := vector.String()
fmt.Println(vectorString) // "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

### Check

```go
func (c *Cvss3x) Check() error
```

验证 CVSS 向量的完整性和有效性。

**验证内容：**
- 检查必需的基础指标是否存在
- 验证指标值的有效性
- 确保版本号的正确性

**示例：**
```go
err := vector.Check()
if err != nil {
    log.Fatalf("向量验证失败: %v", err)
}
```

### Clone

```go
func (c *Cvss3x) Clone() *Cvss3x
```

创建 CVSS 向量的深拷贝。

**示例：**
```go
originalVector := &cvss.Cvss3x{...}
clonedVector := originalVector.Clone()

// 修改克隆的向量不会影响原始向量
clonedVector.MajorVersion = 4
```

## 创建和初始化

### 手动创建

```go
// 创建新的 CVSS 向量
vector := &cvss.Cvss3x{
    MajorVersion: 3,
    MinorVersion: 1,
    Cvss3xBase: &cvss.Cvss3xBase{
        AttackVector:       &vector.AttackVectorNetwork{},
        AttackComplexity:   &vector.AttackComplexityLow{},
        PrivilegesRequired: &vector.PrivilegesRequiredNone{},
        UserInteraction:    &vector.UserInteractionNone{},
        Scope:             &vector.ScopeUnchanged{},
        Confidentiality:   &vector.ConfidentialityHigh{},
        Integrity:         &vector.IntegrityHigh{},
        Availability:      &vector.AvailabilityHigh{},
    },
}
```

### 使用构建器模式

```go
vector := cvss.NewCvss3xBuilder().
    Version(3, 1).
    AttackVector(vector.AttackVectorNetwork{}).
    AttackComplexity(vector.AttackComplexityLow{}).
    PrivilegesRequired(vector.PrivilegesRequiredNone{}).
    UserInteraction(vector.UserInteractionNone{}).
    Scope(vector.ScopeUnchanged{}).
    Confidentiality(vector.ConfidentialityHigh{}).
    Integrity(vector.IntegrityHigh{}).
    Availability(vector.AvailabilityHigh{}).
    Build()
```

## JSON 序列化

### 序列化

```go
vector := &cvss.Cvss3x{...}

// 序列化为 JSON
jsonData, err := json.MarshalIndent(vector, "", "  ")
if err != nil {
    log.Fatal(err)
}

fmt.Println(string(jsonData))
```

### 反序列化

```go
jsonStr := `{
  "major_version": 3,
  "minor_version": 1,
  "base_metrics": {
    "attack_vector": {
      "value": "N",
      "score": 0.85
    }
  }
}`

var vector cvss.Cvss3x
err := json.Unmarshal([]byte(jsonStr), &vector)
if err != nil {
    log.Fatal(err)
}
```

## 使用示例

### 完整示例

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"
    
    "github.com/scagogogo/cvss-parser/pkg/cvss"
    "github.com/scagogogo/cvss-parser/pkg/vector"
)

func main() {
    // 创建 CVSS 向量
    cvssVector := &cvss.Cvss3x{
        MajorVersion: 3,
        MinorVersion: 1,
        Cvss3xBase: &cvss.Cvss3xBase{
            AttackVector:       &vector.AttackVectorNetwork{},
            AttackComplexity:   &vector.AttackComplexityLow{},
            PrivilegesRequired: &vector.PrivilegesRequiredNone{},
            UserInteraction:    &vector.UserInteractionNone{},
            Scope:             &vector.ScopeUnchanged{},
            Confidentiality:   &vector.ConfidentialityHigh{},
            Integrity:         &vector.IntegrityHigh{},
            Availability:      &vector.AvailabilityHigh{},
        },
    }
    
    // 验证向量
    if err := cvssVector.Check(); err != nil {
        log.Fatalf("向量验证失败: %v", err)
    }
    
    // 转换为字符串
    vectorString := cvssVector.String()
    fmt.Printf("CVSS 向量: %s\n", vectorString)
    
    // 序列化为 JSON
    jsonData, err := json.MarshalIndent(cvssVector, "", "  ")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("JSON 表示:\n%s\n", string(jsonData))
    
    // 计算评分
    calculator := cvss.NewCalculator(cvssVector)
    score, err := calculator.Calculate()
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("CVSS 评分: %.1f\n", score)
    fmt.Printf("严重性: %s\n", calculator.GetSeverityRating(score))
}
```

### 向量比较

```go
func compareVectors(v1, v2 *cvss.Cvss3x) {
    fmt.Printf("向量1: %s\n", v1.String())
    fmt.Printf("向量2: %s\n", v2.String())
    
    // 计算评分
    calc1 := cvss.NewCalculator(v1)
    calc2 := cvss.NewCalculator(v2)
    
    score1, _ := calc1.Calculate()
    score2, _ := calc2.Calculate()
    
    fmt.Printf("评分1: %.1f (%s)\n", score1, calc1.GetSeverityRating(score1))
    fmt.Printf("评分2: %.1f (%s)\n", score2, calc2.GetSeverityRating(score2))
    
    // 计算距离
    distCalc := cvss.NewDistanceCalculator(v1, v2)
    distance := distCalc.EuclideanDistance()
    
    fmt.Printf("向量距离: %.3f\n", distance)
}
```

## 最佳实践

### 1. 验证向量

```go
func validateAndProcess(vector *cvss.Cvss3x) error {
    // 总是验证向量
    if err := vector.Check(); err != nil {
        return fmt.Errorf("向量验证失败: %w", err)
    }
    
    // 处理向量...
    return nil
}
```

### 2. 安全的类型断言

```go
func getAttackVectorScore(vector *cvss.Cvss3x) (float64, error) {
    if vector.Cvss3xBase == nil || vector.Cvss3xBase.AttackVector == nil {
        return 0, fmt.Errorf("缺少攻击向量指标")
    }
    
    return vector.Cvss3xBase.AttackVector.GetScore(), nil
}
```

### 3. 深拷贝

```go
func modifyVector(original *cvss.Cvss3x) *cvss.Cvss3x {
    // 创建深拷贝以避免修改原始向量
    modified := original.Clone()
    
    // 安全地修改拷贝
    modified.MinorVersion = 2
    
    return modified
}
```

## 相关文档

- [Calculator 计算器](/zh/api/cvss/calculator)
- [Vector 接口](/zh/api/vector/interface)
- [Parser 解析器](/zh/api/parser/cvss3x-parser)
- [使用示例](/zh/examples/basic)
