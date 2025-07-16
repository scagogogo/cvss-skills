# cvss 包

`cvss` 包是 CVSS Parser 的核心包，提供了 CVSS 3.x 向量的数据结构、评分计算和分析功能。

## 包概述

```go
import "github.com/scagogogo/cvss-parser/pkg/cvss"
```

## 主要类型

### 核心结构

| 类型 | 描述 | 文档链接 |
|------|------|----------|
| `Cvss3x` | CVSS 3.x 向量的主要数据结构 | [详细文档](/api/cvss/cvss3x) |
| `Cvss3xBase` | 基础指标组 | [详细文档](/api/cvss/cvss3x) |
| `Cvss3xTemporal` | 时间指标组 | [详细文档](/api/cvss/cvss3x) |
| `Cvss3xEnvironmental` | 环境指标组 | [详细文档](/api/cvss/cvss3x) |

### 计算器

| 类型 | 描述 | 文档链接 |
|------|------|----------|
| `Calculator` | CVSS 评分计算器 | [详细文档](/api/cvss/calculator) |
| `DistanceCalculator` | 向量距离计算器 | [详细文档](/api/cvss/distance) |

## 快速示例

### 创建 CVSS 向量

```go
// 手动创建向量
cvssVector := cvss.NewCvss3x()
cvssVector.MajorVersion = 3
cvssVector.MinorVersion = 1

// 设置基础指标
cvssVector.Cvss3xBase.AttackVector = &vector.AttackVectorNetwork{}
cvssVector.Cvss3xBase.AttackComplexity = &vector.AttackComplexityLow{}
// ... 设置其他指标
```

### 计算评分

```go
// 创建计算器
calculator := cvss.NewCalculator(cvssVector)

// 计算基础评分
score, err := calculator.Calculate()
if err != nil {
    log.Fatalf("计算失败: %v", err)
}

fmt.Printf("CVSS 评分: %.1f\n", score)
fmt.Printf("严重性: %s\n", calculator.GetSeverityRating(score))
```

### 向量距离计算

```go
// 计算两个向量的距离
distCalc := cvss.NewDistanceCalculator(vector1, vector2)

// 欧几里得距离
euclidean := distCalc.EuclideanDistance()

// 曼哈顿距离
manhattan := distCalc.ManhattanDistance()

fmt.Printf("欧几里得距离: %.3f\n", euclidean)
fmt.Printf("曼哈顿距离: %.3f\n", manhattan)
```

## 功能特性

### 🎯 完整的 CVSS 支持

- **CVSS 3.0/3.1**: 完全支持两个版本
- **所有指标**: 基础、时间、环境指标
- **精确计算**: 严格按照官方规范

### 📊 高级分析

- **距离计算**: 多种距离算法
- **相似度分析**: 向量相似度评估
- **批量处理**: 高效的批量计算

### 🔧 开发者友好

- **类型安全**: 强类型 API 设计
- **零依赖**: 纯 Go 实现
- **高性能**: 优化的计算算法

## 包结构

```
cvss/
├── cvss3x.go              # 主要数据结构
├── cvss3x_base.go         # 基础指标
├── cvss3x_temporal.go     # 时间指标
├── cvss3x_environmental.go # 环境指标
├── calculator.go          # 评分计算器
├── distance.go           # 距离计算器
└── json.go               # JSON 支持
```

## 设计模式

### 组合模式
CVSS 向量使用组合模式，将不同类型的指标组合在一起：

```go
type Cvss3x struct {
    *Cvss3xBase          // 基础指标
    *Cvss3xTemporal      // 时间指标
    *Cvss3xEnvironmental // 环境指标
    
    MajorVersion int     // 主版本号
    MinorVersion int     // 次版本号
}
```

### 策略模式
不同的计算算法使用策略模式实现：

```go
// 基础评分计算
func (c *Calculator) calculateBaseScore() float64 {
    if c.isChangedScope() {
        return c.calculateChangedScopeScore()
    }
    return c.calculateUnchangedScopeScore()
}
```

### 工厂模式
提供便捷的构造函数：

```go
// 创建新的 CVSS 向量
func NewCvss3x() *Cvss3x

// 创建计算器
func NewCalculator(cvss *Cvss3x) *Calculator

// 创建距离计算器
func NewDistanceCalculator(v1, v2 *Cvss3x) *DistanceCalculator
```

## 性能考虑

### 内存效率
- 使用指针避免不必要的复制
- 延迟初始化可选指标
- 最小化内存分配

### 计算优化
- 缓存中间计算结果
- 避免重复计算
- 使用高效的数学运算

## 下一步

深入了解具体功能：

- 📖 [Cvss3x 数据结构](/api/cvss/cvss3x)
- 🧮 [Calculator 评分计算](/api/cvss/calculator)
- 📏 [DistanceCalculator 距离计算](/api/cvss/distance)
- 📄 [JSON 支持](/api/cvss/json)
