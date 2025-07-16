# Calculator 计算器

`Calculator` 是 CVSS Parser 中用于计算 CVSS 评分的核心组件。它提供了完整的 CVSS 3.x 评分计算功能，包括基础评分、时间评分和环境评分。

## 接口定义

```go
type Calculator interface {
    Calculate() (float64, error)
    CalculateBaseScore() (float64, error)
    CalculateTemporalScore() (float64, error)
    CalculateEnvironmentalScore() (float64, error)
    GetSeverityRating(score float64) string
}
```

## 创建计算器

### NewCalculator

```go
func NewCalculator(vector *Cvss3x) Calculator
```

创建一个新的计算器实例。

**参数：**
- `vector`: 要计算的 CVSS 3.x 向量

**返回值：**
- `Calculator`: 计算器实例

**示例：**
```go
calculator := cvss.NewCalculator(cvssVector)
```

## 主要方法

### Calculate

```go
func (c *Calculator) Calculate() (float64, error)
```

计算最终的 CVSS 评分。根据向量中包含的指标类型，自动选择合适的计算方法：
- 仅基础指标：返回基础评分
- 包含时间指标：返回时间评分
- 包含环境指标：返回环境评分

**返回值：**
- `float64`: CVSS 评分 (0.0-10.0)
- `error`: 计算错误

**示例：**
```go
score, err := calculator.Calculate()
if err != nil {
    log.Fatalf("计算失败: %v", err)
}
fmt.Printf("CVSS 评分: %.1f\n", score)
```

### CalculateBaseScore

```go
func (c *Calculator) CalculateBaseScore() (float64, error)
```

计算 CVSS 基础评分，仅基于基础指标。

**计算公式：**
```
如果 (影响子分 <= 0)
    基础评分 = 0
否则
    如果 (范围 == 不变)
        基础评分 = 向上取整(最小值((影响 + 可利用性), 10))
    否则
        基础评分 = 向上取整(最小值(1.08 × (影响 + 可利用性), 10))
```

**示例：**
```go
baseScore, err := calculator.CalculateBaseScore()
if err != nil {
    log.Fatalf("基础评分计算失败: %v", err)
}
fmt.Printf("基础评分: %.1f\n", baseScore)
```

### CalculateTemporalScore

```go
func (c *Calculator) CalculateTemporalScore() (float64, error)
```

计算时间评分，基于基础评分和时间指标。

**计算公式：**
```
时间评分 = 向上取整(基础评分 × 利用代码成熟度 × 修复级别 × 报告置信度)
```

**示例：**
```go
temporalScore, err := calculator.CalculateTemporalScore()
if err != nil {
    log.Fatalf("时间评分计算失败: %v", err)
}
fmt.Printf("时间评分: %.1f\n", temporalScore)
```

### CalculateEnvironmentalScore

```go
func (c *Calculator) CalculateEnvironmentalScore() (float64, error)
```

计算环境评分，基于修改后的基础指标和环境指标。

**计算公式：**
```
修改后影响 = 最小值(1 - [(1-机密性需求×修改后机密性影响) × (1-完整性需求×修改后完整性影响) × (1-可用性需求×修改后可用性影响)], 0.915)

修改后可利用性 = 8.22 × 修改后攻击向量 × 修改后攻击复杂性 × 修改后权限要求 × 修改后用户交互

如果 (修改后影响 <= 0)
    环境评分 = 0
否则
    如果 (修改后范围 == 不变)
        环境评分 = 向上取整(向上取整(最小值((修改后影响 + 修改后可利用性), 10)) × 利用代码成熟度 × 修复级别 × 报告置信度)
    否则
        环境评分 = 向上取整(向上取整(最小值(1.08 × (修改后影响 + 修改后可利用性), 10)) × 利用代码成熟度 × 修复级别 × 报告置信度)
```

**示例：**
```go
envScore, err := calculator.CalculateEnvironmentalScore()
if err != nil {
    log.Fatalf("环境评分计算失败: %v", err)
}
fmt.Printf("环境评分: %.1f\n", envScore)
```

### GetSeverityRating

```go
func (c *Calculator) GetSeverityRating(score float64) string
```

根据 CVSS 评分获取对应的严重性等级。

**评分范围和等级：**

| 评分范围 | 严重性等级 | 英文 |
|----------|------------|------|
| 0.0 | 无 | None |
| 0.1-3.9 | 低危 | Low |
| 4.0-6.9 | 中危 | Medium |
| 7.0-8.9 | 高危 | High |
| 9.0-10.0 | 严重 | Critical |

**示例：**
```go
score := 7.5
severity := calculator.GetSeverityRating(score)
fmt.Printf("评分 %.1f 对应严重性: %s\n", score, severity) // "High"
```

## 完整示例

### 基本使用

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cvss-parser/pkg/cvss"
    "github.com/scagogogo/cvss-parser/pkg/parser"
)

func main() {
    // 解析 CVSS 向量
    vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    p := parser.NewCvss3xParser(vectorStr)
    vector, err := p.Parse()
    if err != nil {
        log.Fatalf("解析失败: %v", err)
    }
    
    // 创建计算器
    calculator := cvss.NewCalculator(vector)
    
    // 计算各种评分
    baseScore, err := calculator.CalculateBaseScore()
    if err != nil {
        log.Fatalf("基础评分计算失败: %v", err)
    }
    
    finalScore, err := calculator.Calculate()
    if err != nil {
        log.Fatalf("最终评分计算失败: %v", err)
    }
    
    severity := calculator.GetSeverityRating(finalScore)
    
    // 输出结果
    fmt.Printf("CVSS 向量: %s\n", vectorStr)
    fmt.Printf("基础评分: %.1f\n", baseScore)
    fmt.Printf("最终评分: %.1f\n", finalScore)
    fmt.Printf("严重性等级: %s\n", severity)
}
```

### 批量计算

```go
func calculateBatch(vectors []string) {
    for _, vectorStr := range vectors {
        p := parser.NewCvss3xParser(vectorStr)
        vector, err := p.Parse()
        if err != nil {
            fmt.Printf("解析失败 %s: %v\n", vectorStr, err)
            continue
        }
        
        calculator := cvss.NewCalculator(vector)
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

### 详细分析

```go
func detailedAnalysis(vectorStr string) {
    p := parser.NewCvss3xParser(vectorStr)
    vector, err := p.Parse()
    if err != nil {
        log.Fatalf("解析失败: %v", err)
    }
    
    calculator := cvss.NewCalculator(vector)
    
    // 计算所有类型的评分
    baseScore, _ := calculator.CalculateBaseScore()
    
    var temporalScore, envScore float64
    
    // 检查是否有时间指标
    if vector.Cvss3xTemporal != nil {
        temporalScore, _ = calculator.CalculateTemporalScore()
    }
    
    // 检查是否有环境指标
    if vector.Cvss3xEnvironmental != nil {
        envScore, _ = calculator.CalculateEnvironmentalScore()
    }
    
    finalScore, _ := calculator.Calculate()
    severity := calculator.GetSeverityRating(finalScore)
    
    fmt.Printf("=== CVSS 评分分析 ===\n")
    fmt.Printf("向量: %s\n", vectorStr)
    fmt.Printf("基础评分: %.1f\n", baseScore)
    
    if temporalScore > 0 {
        fmt.Printf("时间评分: %.1f\n", temporalScore)
    }
    
    if envScore > 0 {
        fmt.Printf("环境评分: %.1f\n", envScore)
    }
    
    fmt.Printf("最终评分: %.1f\n", finalScore)
    fmt.Printf("严重性等级: %s\n", severity)
}
```

## 错误处理

计算器可能返回以下类型的错误：

### 常见错误

```go
score, err := calculator.Calculate()
if err != nil {
    switch e := err.(type) {
    case *cvss.InvalidVectorError:
        fmt.Printf("无效向量: %s\n", e.Message)
    case *cvss.MissingMetricError:
        fmt.Printf("缺少必需指标: %s\n", e.Metric)
    case *cvss.CalculationError:
        fmt.Printf("计算错误: %s\n", e.Message)
    default:
        fmt.Printf("未知错误: %v\n", err)
    }
}
```

### 验证向量

```go
func validateVector(vector *cvss.Cvss3x) error {
    // 检查基础指标是否完整
    if vector.Cvss3xBase.AttackVector == nil {
        return fmt.Errorf("缺少攻击向量指标")
    }
    
    if vector.Cvss3xBase.AttackComplexity == nil {
        return fmt.Errorf("缺少攻击复杂性指标")
    }
    
    // ... 检查其他必需指标
    
    return nil
}
```

## 性能优化

### 重用计算器

```go
// 对于大量计算，重用计算器实例
calculator := cvss.NewCalculator(nil)

for _, vector := range vectors {
    calculator.SetVector(vector)
    score, err := calculator.Calculate()
    if err != nil {
        continue
    }
    
    // 处理评分...
}
```

### 并发计算

```go
func concurrentCalculation(vectors []*cvss.Cvss3x) []float64 {
    results := make([]float64, len(vectors))
    var wg sync.WaitGroup
    
    for i, vector := range vectors {
        wg.Add(1)
        go func(index int, v *cvss.Cvss3x) {
            defer wg.Done()
            
            calculator := cvss.NewCalculator(v)
            score, err := calculator.Calculate()
            if err != nil {
                results[index] = 0
                return
            }
            
            results[index] = score
        }(i, vector)
    }
    
    wg.Wait()
    return results
}
```

## 相关文档

- [Cvss3x 数据结构](/zh/api/cvss/cvss3x)
- [DistanceCalculator 距离计算](/zh/api/cvss/distance)
- [使用示例](/zh/examples/basic)
- [CVSS 规范](https://www.first.org/cvss/v3.1/specification-document)
