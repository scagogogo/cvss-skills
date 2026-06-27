---
layout: home

hero:
  name: "CVSS Skills"
  text: "Go 语言 CVSS 解析与评分库"
  tagline: 强大、灵活、易用的 CVSS 3.0/3.1 解析、评分和分析库
  actions:
    - theme: brand
      text: 快速开始
      link: /zh/api/getting-started
    - theme: alt
      text: 查看示例
      link: /zh/examples/
    - theme: alt
      text: GitHub
      link: https://github.com/scagogogo/cvss-skills

features:
  - icon: 🚀
    title: 高性能解析
    details: 快速准确地解析 CVSS 3.0 和 3.1 向量字符串，支持所有标准指标和扩展指标。

  - icon: 🧮
    title: 完整评分计算
    details: 支持基础评分、时间评分和环境评分的完整计算，严格遵循 CVSS 规范。

  - icon: 📊
    title: 向量分析
    details: 提供向量比较、距离计算和相似度分析等高级功能，满足复杂的安全评估需求。

  - icon: 🔧
    title: 灵活配置
    details: 支持严格模式和容错模式，可根据不同场景选择合适的解析策略。

  - icon: 📄
    title: JSON 支持
    details: 完整的 JSON 序列化和反序列化支持，方便与其他系统集成和数据存储。

  - icon: 🧪
    title: 高质量代码
    details: 完整的测试覆盖，详细的文档和示例，确保代码质量和可维护性。
---

## 快速安装

```bash
go get github.com/scagogogo/cvss-skills
```

## 简单示例

```go
package main

import (
    "fmt"
    "log"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    // 解析 CVSS 向量
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

    fmt.Printf("CVSS 评分: %.1f\n", score)
    fmt.Printf("严重性: %s\n", calculator.GetSeverityRating(score))
}
```

## 主要特性

### 🎯 完整的 CVSS 支持

- **CVSS 3.0 和 3.1**: 完全支持两个版本的规范
- **所有指标类型**: 基础指标、时间指标、环境指标
- **严格验证**: 确保向量格式和值的正确性

### 📈 高级分析功能

- **向量比较**: 计算两个 CVSS 向量的相似度
- **距离计算**: 多种距离算法支持
- **批量处理**: 高效处理大量向量数据

### 🔌 易于集成

- **JSON 支持**: 完整的序列化和反序列化
- **错误处理**: 详细的错误信息和恢复机制
- **文档完善**: 丰富的示例和 API 文档

## 使用场景

### 🛡️ 安全评估

```go
// 评估漏洞严重性
vectors := []string{
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
}

for _, vectorStr := range vectors {
    // 解析和评估...
}
```

### 📊 风险分析

```go
// 计算向量距离
distCalc := cvss.NewDistanceCalculator(vector1, vector2)
distance := distCalc.EuclideanDistance()
fmt.Printf("向量距离: %.3f\n", distance)
```

### 💾 数据存储

```go
// JSON 序列化
jsonData, err := json.Marshal(cvssVector)
if err != nil {
    log.Fatal(err)
}
```

## 开始使用

1. **[快速开始](/zh/api/getting-started)** - 5分钟上手指南
2. **[API 文档](/zh/api/)** - 完整的 API 参考
3. **[示例代码](/zh/examples/)** - 丰富的使用示例

## 社区和支持

- 📖 [完整文档](https://scagogogo.github.io/cvss-skills/)
- 🐛 [问题反馈](https://github.com/scagogogo/cvss-skills/issues)
- 💬 [讨论区](https://github.com/scagogogo/cvss-skills/discussions)
- 📧 [联系我们](mailto:your-email@example.com)

---

<div style="text-align: center; margin-top: 2rem;">
  <p>
    <strong>CVSS Skills</strong> - 让 CVSS 处理变得简单高效
  </p>
  <p>
    <a href="/zh/api/getting-started">立即开始</a> |
    <a href="https://github.com/scagogogo/cvss-skills">查看源码</a> |
    <a href="/zh/examples/">浏览示例</a>
  </p>
</div>
