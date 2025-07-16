# API 参考

CVSS Parser 提供了一套完整的 Go 语言 API，用于解析、计算和处理 CVSS (通用漏洞评分系统) 向量。

## 包结构

CVSS Parser 包含三个主要的包：

### 📦 [cvss](/api/cvss/)
核心包，包含 CVSS 数据结构、评分计算器和距离计算功能。

**主要类型：**
- `Cvss3x` - CVSS 3.x 向量表示
- `Calculator` - CVSS 评分计算器
- `DistanceCalculator` - 向量距离计算器

### 📦 [parser](/api/parser/)
解析包，负责将 CVSS 向量字符串解析为结构化数据。

**主要类型：**
- `Cvss3xParser` - CVSS 3.x 向量解析器
- `VectorParser` - 通用向量解析器

### 📦 [vector](/api/vector/)
向量包，定义了 CVSS 各种指标的接口和实现。

**主要类型：**
- `Vector` - 向量接口
- 各种指标实现（攻击向量、攻击复杂性等）

## 快速导航

### 🚀 新手入门
- [快速开始](/api/getting-started) - 5分钟上手指南
- [基础示例](/examples/basic) - 最简单的使用示例

### 🔧 核心功能
- [解析CVSS向量](/api/parser/cvss3x-parser) - 字符串解析
- [计算CVSS评分](/api/cvss/calculator) - 评分计算
- [向量距离计算](/api/cvss/distance) - 相似度分析

### 📊 高级功能
- [JSON支持](/api/cvss/json) - 序列化和反序列化
- [时间指标](/api/vector/temporal-metrics) - 时间评分
- [环境指标](/api/vector/environmental-metrics) - 环境评分

## 设计原则

### 类型安全
所有 API 都使用强类型设计，在编译时捕获错误：

```go
// 类型安全的向量创建
vector := &cvss.Cvss3x{
    MajorVersion: 3,
    MinorVersion: 1,
    Cvss3xBase: &cvss.Cvss3xBase{
        AttackVector: &vector.AttackVectorNetwork{},
        // ...
    },
}
```

### 错误处理
遵循 Go 语言惯例，明确的错误处理：

```go
score, err := calculator.Calculate()
if err != nil {
    return fmt.Errorf("计算评分失败: %w", err)
}
```

### 零依赖
纯 Go 实现，无外部依赖，易于集成：

```go
import "github.com/scagogogo/cvss-parser/pkg/cvss"
```

## 版本兼容性

| CVSS Parser 版本 | Go 版本要求 | CVSS 规范支持 |
|-----------------|------------|--------------|
| v1.x.x          | Go 1.19+   | CVSS 3.0, 3.1 |

## 性能特性

- **高性能解析**: 优化的字符串解析算法
- **内存效率**: 最小化内存分配
- **并发安全**: 所有计算器都是并发安全的

## 下一步

选择你感兴趣的主题：

- 📖 [快速开始指南](/api/getting-started)
- 🔍 [浏览完整示例](/examples/)
- 🛠️ [查看具体包文档](/api/cvss/)
