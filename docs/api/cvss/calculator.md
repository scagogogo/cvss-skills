# Calculator - CVSS 评分计算器

`Calculator` 是 CVSS Parser 的评分计算引擎，负责根据 CVSS 向量计算基础、时间和环境评分。

## 类型定义

```go
type Calculator struct {
    cvss *Cvss3x
}
```

## 构造函数

### NewCalculator

```go
func NewCalculator(cvss *Cvss3x) *Calculator
```

创建一个新的 CVSS 评分计算器。

**参数：**
- `cvss` - 要计算评分的 CVSS 向量

**返回值：**
- `*Calculator` - 计算器实例

**示例：**
```go
calculator := cvss.NewCalculator(cvssVector)
```

## 主要方法

### Calculate

```go
func (c *Calculator) Calculate() (float64, error)
```

计算 CVSS 评分。根据向量中设置的指标，自动选择计算基础评分、时间评分或环境评分。

**返回值：**
- `float64` - 计算得出的评分 (0.0-10.0)
- `error` - 计算过程中的错误

**计算逻辑：**
1. 如果只有基础指标 → 返回基础评分
2. 如果有时间指标 → 返回时间评分
3. 如果有环境指标 → 返回环境评分

**示例：**
```go
score, err := calculator.Calculate()
if err != nil {
    log.Fatalf("计算失败: %v", err)
}
fmt.Printf("CVSS 评分: %.1f\n", score)
```

### GetSeverityRating

```go
func (c *Calculator) GetSeverityRating(score float64) string
```

根据评分获取严重性级别。

**参数：**
- `score` - CVSS 评分 (0.0-10.0)

**返回值：**
- `string` - 严重性级别

**严重性级别：**
| 评分范围 | 严重性级别 |
|----------|------------|
| 0.0 | None |
| 0.1-3.9 | Low |
| 4.0-6.9 | Medium |
| 7.0-8.9 | High |
| 9.0-10.0 | Critical |

**示例：**
```go
severity := calculator.GetSeverityRating(9.8)
fmt.Println(severity) // "Critical"
```

## 评分计算详解

### 基础评分计算

基础评分由影响子评分和可利用性子评分组成：

```go
func (c *Calculator) calculateBaseScore() float64 {
    impactSubScore := c.calculateImpactSubScore()
    exploitabilitySubScore := c.calculateExploitabilitySubScore()
    
    if c.isChangedScope() {
        return roundUp(math.Min(1.08*(impactSubScore+exploitabilitySubScore), 10))
    } else {
        return roundUp(math.Min(impactSubScore+exploitabilitySubScore, 10))
    }
}
```

#### 影响子评分

影响子评分基于机密性、完整性和可用性的影响：

**公式：**
- 影响基本分数 = 1 - ((1-C) × (1-I) × (1-A))
- 如果范围未改变：影响子评分 = 6.42 × 影响基本分数
- 如果范围改变：影响子评分 = 7.52 × (影响基本分数-0.029) - 3.25 × (影响基本分数×0.9731-0.02)^13

#### 可利用性子评分

可利用性子评分基于攻击向量、攻击复杂性、所需权限和用户交互：

**公式：**
- 可利用性子评分 = 8.22 × AV × AC × PR × UI

**特殊处理：**
- 当范围改变且 PR=L 时，PR 值使用 0.68 而不是 0.62
- 当范围改变且 PR=H 时，PR 值使用 0.50 而不是 0.27

### 时间评分计算

时间评分在基础评分基础上应用时间因素：

```go
func (c *Calculator) calculateTemporalScore(baseScore float64) float64 {
    e := c.cvss.Cvss3xTemporal.ExploitCodeMaturity.GetScore()
    rl := c.cvss.Cvss3xTemporal.RemediationLevel.GetScore()
    rc := c.cvss.Cvss3xTemporal.ReportConfidence.GetScore()
    
    return roundUp(baseScore * e * rl * rc)
}
```

### 环境评分计算

环境评分考虑修改后的基础指标和安全需求：

1. 使用修改后的基础指标重新计算影响和可利用性
2. 应用安全需求调整因子
3. 计算最终环境评分

## 完整示例

### 基础评分计算

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cvss-parser/pkg/parser"
    "github.com/scagogogo/cvss-parser/pkg/cvss"
)

func main() {
    // 解析基础向量
    p := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    cvssVector, err := p.Parse()
    if err != nil {
        log.Fatalf("解析失败: %v", err)
    }
    
    // 计算基础评分
    calculator := cvss.NewCalculator(cvssVector)
    score, err := calculator.Calculate()
    if err != nil {
        log.Fatalf("计算失败: %v", err)
    }
    
    fmt.Printf("基础评分: %.1f\n", score)
    fmt.Printf("严重性: %s\n", calculator.GetSeverityRating(score))
}
```

### 时间评分计算

```go
// 包含时间指标的向量
vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C"
p := parser.NewCvss3xParser(vectorStr)
cvssVector, err := p.Parse()
if err != nil {
    log.Fatalf("解析失败: %v", err)
}

calculator := cvss.NewCalculator(cvssVector)
score, err := calculator.Calculate()
if err != nil {
    log.Fatalf("计算失败: %v", err)
}

fmt.Printf("时间评分: %.1f\n", score)
```

### 环境评分计算

```go
// 包含环境指标的向量
vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H"
p := parser.NewCvss3xParser(vectorStr)
cvssVector, err := p.Parse()
if err != nil {
    log.Fatalf("解析失败: %v", err)
}

calculator := cvss.NewCalculator(cvssVector)
score, err := calculator.Calculate()
if err != nil {
    log.Fatalf("计算失败: %v", err)
}

fmt.Printf("环境评分: %.1f\n", score)
```

### 批量计算

```go
func calculateBatch(vectors []string) {
    for _, vectorStr := range vectors {
        p := parser.NewCvss3xParser(vectorStr)
        cvssVector, err := p.Parse()
        if err != nil {
            fmt.Printf("解析失败 %s: %v\n", vectorStr, err)
            continue
        }
        
        calculator := cvss.NewCalculator(cvssVector)
        score, err := calculator.Calculate()
        if err != nil {
            fmt.Printf("计算失败 %s: %v\n", vectorStr, err)
            continue
        }
        
        severity := calculator.GetSeverityRating(score)
        fmt.Printf("%s -> %.1f (%s)\n", vectorStr, score, severity)
    }
}
```

## 性能考虑

### 计算优化
- 计算器是无状态的，可以重复使用
- 中间结果会被缓存以避免重复计算
- 数学运算使用高效的算法

### 内存使用
- 计算器本身占用内存很少
- 可以为每个向量创建新的计算器实例
- 支持并发计算

## 错误处理

常见的计算错误：

```go
score, err := calculator.Calculate()
if err != nil {
    switch {
    case strings.Contains(err.Error(), "can not empty"):
        // 缺少必需的基础指标
        fmt.Println("向量不完整")
    case strings.Contains(err.Error(), "invalid"):
        // 指标值无效
        fmt.Println("指标值无效")
    default:
        fmt.Printf("计算错误: %v\n", err)
    }
}
```

## 最佳实践

### 1. 错误检查
```go
// 始终检查计算错误
score, err := calculator.Calculate()
if err != nil {
    return fmt.Errorf("CVSS 计算失败: %w", err)
}
```

### 2. 向量验证
```go
// 计算前验证向量
if err := cvssVector.Check(); err != nil {
    return fmt.Errorf("向量无效: %w", err)
}
```

### 3. 并发使用
```go
// 计算器是并发安全的
go func() {
    calculator := cvss.NewCalculator(cvssVector)
    score, _ := calculator.Calculate()
    // 处理结果
}()
```

## 相关文档

- [Cvss3x 数据结构](/api/cvss/cvss3x)
- [DistanceCalculator 距离计算](/api/cvss/distance)
- [Vector 接口](/api/vector/interface)
