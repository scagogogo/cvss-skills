# Cvss3x 数据结构

`Cvss3x` 是 CVSS Parser 的核心数据结构，表示一个完整的 CVSS 3.x 向量。

## 类型定义

```go
type Cvss3x struct {
    *Cvss3xBase          // 基础指标组
    *Cvss3xTemporal      // 时间指标组
    *Cvss3xEnvironmental // 环境指标组
    
    MajorVersion int     // 主版本号 (3)
    MinorVersion int     // 次版本号 (0 或 1)
}
```

## 构造函数

### NewCvss3x

```go
func NewCvss3x() *Cvss3x
```

创建一个新的 CVSS 3.x 向量实例，所有指标组都会被初始化。

**示例：**
```go
cvss := cvss.NewCvss3x()
cvss.MajorVersion = 3
cvss.MinorVersion = 1
```

## 方法

### Check

```go
func (x *Cvss3x) Check() error
```

验证 CVSS 向量的完整性和有效性。检查所有必需的基础指标是否已设置。

**返回值：**
- `error` - 如果向量无效则返回错误，否则返回 nil

**示例：**
```go
if err := cvss.Check(); err != nil {
    log.Fatalf("CVSS 向量无效: %v", err)
}
```

### String

```go
func (x *Cvss3x) String() string
```

将 CVSS 向量转换为标准的字符串表示形式。

**返回值：**
- `string` - CVSS 向量字符串，如 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

**示例：**
```go
vectorStr := cvss.String()
fmt.Println(vectorStr) // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

## 基础指标组 (Cvss3xBase)

基础指标是 CVSS 评分的核心，包含8个必需指标：

```go
type Cvss3xBase struct {
    AttackVector       vector.Vector // 攻击向量 (AV)
    AttackComplexity   vector.Vector // 攻击复杂性 (AC)
    PrivilegesRequired vector.Vector // 所需权限 (PR)
    UserInteraction    vector.Vector // 用户交互 (UI)
    Scope              vector.Vector // 影响范围 (S)
    Confidentiality    vector.Vector // 机密性影响 (C)
    Integrity          vector.Vector // 完整性影响 (I)
    Availability       vector.Vector // 可用性影响 (A)
}
```

### 基础指标详解

| 指标 | 简写 | 可能值 | 描述 |
|------|------|--------|------|
| 攻击向量 | AV | N(网络), A(相邻), L(本地), P(物理) | 攻击者如何访问易受攻击的组件 |
| 攻击复杂性 | AC | L(低), H(高) | 成功攻击所需的条件复杂性 |
| 所需权限 | PR | N(无), L(低), H(高) | 攻击者在攻击前必须拥有的权限级别 |
| 用户交互 | UI | N(无), R(需要) | 是否需要用户参与才能成功攻击 |
| 影响范围 | S | U(不变), C(改变) | 攻击是否影响其他组件 |
| 机密性影响 | C | N(无), L(低), H(高) | 对信息机密性的影响 |
| 完整性影响 | I | N(无), L(低), H(高) | 对信息完整性的影响 |
| 可用性影响 | A | N(无), L(低), H(高) | 对信息可用性的影响 |

**示例：**
```go
// 设置基础指标
cvss.Cvss3xBase.AttackVector = &vector.AttackVectorNetwork{}
cvss.Cvss3xBase.AttackComplexity = &vector.AttackComplexityLow{}
cvss.Cvss3xBase.PrivilegesRequired = &vector.PrivilegesRequiredNone{}
cvss.Cvss3xBase.UserInteraction = &vector.UserInteractionNone{}
cvss.Cvss3xBase.Scope = &vector.ScopeUnchanged{}
cvss.Cvss3xBase.Confidentiality = &vector.ConfidentialityHigh{}
cvss.Cvss3xBase.Integrity = &vector.IntegrityHigh{}
cvss.Cvss3xBase.Availability = &vector.AvailabilityHigh{}
```

## 时间指标组 (Cvss3xTemporal)

时间指标反映了漏洞随时间变化的特征：

```go
type Cvss3xTemporal struct {
    ExploitCodeMaturity vector.Vector // 漏洞利用代码成熟度 (E)
    RemediationLevel    vector.Vector // 修复级别 (RL)
    ReportConfidence    vector.Vector // 报告可信度 (RC)
}
```

### 时间指标详解

| 指标 | 简写 | 可能值 | 描述 |
|------|------|--------|------|
| 漏洞利用代码成熟度 | E | X(未定义), U(未验证), P(概念验证), F(功能性), H(高) | 可用的漏洞利用代码的成熟度 |
| 修复级别 | RL | X(未定义), O(官方修复), T(临时修复), W(解决方案), U(不可用) | 可用的修复措施 |
| 报告可信度 | RC | X(未定义), U(未知), R(合理), C(确认) | 漏洞报告的可信度 |

## 环境指标组 (Cvss3xEnvironmental)

环境指标允许根据特定环境调整评分：

```go
type Cvss3xEnvironmental struct {
    // 安全需求
    ConfidentialityRequirement vector.Vector // 机密性需求 (CR)
    IntegrityRequirement       vector.Vector // 完整性需求 (IR)
    AvailabilityRequirement    vector.Vector // 可用性需求 (AR)
    
    // 修改后的基础指标
    ModifiedAttackVector       vector.Vector // 修改的攻击向量 (MAV)
    ModifiedAttackComplexity   vector.Vector // 修改的攻击复杂性 (MAC)
    ModifiedPrivilegesRequired vector.Vector // 修改的所需权限 (MPR)
    ModifiedUserInteraction    vector.Vector // 修改的用户交互 (MUI)
    ModifiedScope              vector.Vector // 修改的影响范围 (MS)
    ModifiedConfidentiality    vector.Vector // 修改的机密性影响 (MC)
    ModifiedIntegrity          vector.Vector // 修改的完整性影响 (MI)
    ModifiedAvailability       vector.Vector // 修改的可用性影响 (MA)
}
```

## 完整示例

### 创建完整的 CVSS 向量

```go
package main

import (
    "fmt"
    "github.com/scagogogo/cvss-parser/pkg/cvss"
    "github.com/scagogogo/cvss-parser/pkg/vector"
)

func main() {
    // 创建新的 CVSS 向量
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
    
    // 输出向量字符串
    fmt.Printf("CVSS 向量: %s\n", cvssVector.String())
}
```

### 使用时间指标

```go
// 设置时间指标
cvssVector.Cvss3xTemporal.ExploitCodeMaturity = &vector.ExploitCodeMaturityFunctional{}
cvssVector.Cvss3xTemporal.RemediationLevel = &vector.RemediationLevelOfficialFix{}
cvssVector.Cvss3xTemporal.ReportConfidence = &vector.ReportConfidenceConfirmed{}
```

### 使用环境指标

```go
// 设置安全需求
cvssVector.Cvss3xEnvironmental.ConfidentialityRequirement = &vector.ConfidentialityRequirementHigh{}
cvssVector.Cvss3xEnvironmental.IntegrityRequirement = &vector.IntegrityRequirementMedium{}
cvssVector.Cvss3xEnvironmental.AvailabilityRequirement = &vector.AvailabilityRequirementLow{}

// 修改基础指标
cvssVector.Cvss3xEnvironmental.ModifiedAttackVector = &vector.AttackVectorLocal{}
```

## 最佳实践

### 1. 始终验证向量
```go
if err := cvss.Check(); err != nil {
    return fmt.Errorf("CVSS 向量无效: %w", err)
}
```

### 2. 使用工厂函数
```go
// 推荐
cvss := cvss.NewCvss3x()

// 不推荐
cvss := &cvss.Cvss3x{}
```

### 3. 设置版本信息
```go
cvss.MajorVersion = 3
cvss.MinorVersion = 1  // 或 0
```

## JSON 支持

Cvss3x 结构支持 JSON 序列化和反序列化：

```go
// 序列化为 JSON
jsonData, err := json.Marshal(cvssVector)
if err != nil {
    log.Fatalf("JSON 序列化失败: %v", err)
}

// 从 JSON 反序列化
var cvss cvss.Cvss3x
err = json.Unmarshal(jsonData, &cvss)
if err != nil {
    log.Fatalf("JSON 反序列化失败: %v", err)
}
```

## 相关文档

- [Calculator - 评分计算](/api/cvss/calculator)
- [Vector 接口](/api/vector/interface)
- [Parser - 字符串解析](/api/parser/cvss3x-parser)
