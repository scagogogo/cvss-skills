---
layout: home

hero:
  name: "CVSS Parser"
  text: "Go语言CVSS解析器"
  tagline: "强大、易用的CVSS 3.x向量解析和计算库"
  image:
    src: /logo.svg
    alt: CVSS Parser
  actions:
    - theme: brand
      text: 快速开始
      link: /api/getting-started
    - theme: alt
      text: API文档
      link: /api/
    - theme: alt
      text: 查看GitHub
      link: https://github.com/scagogogo/cvss

features:
  - icon: 🚀
    title: 高性能解析
    details: 快速准确地解析CVSS 3.0和3.1向量字符串，支持完整的基础、时间和环境指标
  - icon: 🧮
    title: 精确计算
    details: 严格按照CVSS规范计算基础、时间和环境评分，支持所有评分算法
  - icon: 📊
    title: 向量分析
    details: 提供向量距离计算、相似度分析和比较功能，支持多种距离算法
  - icon: 🔧
    title: 易于集成
    details: 简洁的API设计，完整的类型安全，支持JSON序列化和反序列化
  - icon: 📖
    title: 完整文档
    details: 详细的API文档、丰富的示例代码和最佳实践指南
  - icon: ✅
    title: 高质量代码
    details: 98%+测试覆盖率，严格的代码质量控制，持续集成验证
---

## 快速开始

安装CVSS Parser：

```bash
go get github.com/scagogogo/cvss
```

基本使用示例：

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cvss-parser/pkg/parser"
    "github.com/scagogogo/cvss-parser/pkg/cvss"
)

func main() {
    // 解析CVSS向量
    p := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    cvssVector, err := p.Parse()
    if err != nil {
        log.Fatalf("解析失败: %v", err)
    }
    
    // 计算评分
    calculator := cvss.NewCalculator(cvssVector)
    score, err := calculator.Calculate()
    if err != nil {
        log.Fatalf("计算失败: %v", err)
    }
    
    fmt.Printf("CVSS评分: %.1f\n", score)
    fmt.Printf("严重性: %s\n", calculator.GetSeverityRating(score))
}
```

## 主要特性

### 🎯 完整的CVSS支持

- **CVSS 3.0/3.1**: 完全支持CVSS 3.0和3.1规范
- **所有指标类型**: 基础指标、时间指标、环境指标
- **精确计算**: 严格按照官方算法实现

### 🔍 强大的解析能力

- **灵活解析**: 支持完整和部分CVSS向量
- **错误处理**: 详细的错误信息和验证
- **类型安全**: 强类型API设计

### 📈 高级分析功能

- **距离计算**: 欧几里得距离、曼哈顿距离等
- **相似度分析**: 向量相似度计算
- **批量处理**: 支持批量向量处理

### 🛠️ 开发者友好

- **零依赖**: 纯Go实现，无外部依赖
- **高性能**: 优化的解析和计算算法
- **易于测试**: 完整的测试套件和Mock支持

## 下一步

- [查看API文档](/api/) - 了解完整的API参考
- [浏览示例](/examples/) - 学习如何使用各种功能
- [GitHub仓库](https://github.com/scagogogo/cvss) - 查看源代码和贡献指南
