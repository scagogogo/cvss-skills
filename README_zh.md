# CVSS 解析器

[![Go Tests and Examples](https://github.com/scagogogo/cvss/actions/workflows/go-test.yml/badge.svg)](https://github.com/scagogogo/cvss/actions/workflows/go-test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/scagogogo/cvss)](https://goreportcard.com/report/github.com/scagogogo/cvss)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**语言**: [English](README.md) | [简体中文](README_zh.md)

CVSS 解析器是一个 Go 语言库，用于解析、计算和处理 CVSS (通用漏洞评分系统) 向量。支持 CVSS 3.0 和 3.1 版本，提供了全面的功能以满足漏洞管理和安全评估的需求。

## 📖 文档

**🌐 [完整文档网站](https://scagogogo.github.io/cvss/)**

访问我们的综合文档网站获取：
- 📚 **[API 参考](https://scagogogo.github.io/cvss/api/)** - 完整的 API 文档
- 💡 **[示例和教程](https://scagogogo.github.io/cvss/examples/)** - 实用的使用示例
- 🚀 **[快速开始指南](https://scagogogo.github.io/cvss/api/getting-started)** - 5分钟快速上手
- 🌍 **[中文文档](https://scagogogo.github.io/cvss/zh/)** - 完整的中文文档

## 特性

- 支持 CVSS 3.0 和 3.1 向量的解析和计算
- 计算基础、时间和环境评分
- 提供 JSON 输出和格式化功能
- 向量比较和相似度计算
- 严格模式和容错模式解析
- 完整的文档和示例
- 高测试覆盖率

## 安装

```bash
go get github.com/scagogogo/cvss
```

## 快速开始

解析和计算 CVSS 评分：

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

更多示例请查看 [examples](./examples) 目录。

## 📚 学习资源

### 快速开始
- [5分钟快速上手](https://scagogogo.github.io/cvss/api/getting-started) - 最快的入门方式
- [基础示例](https://scagogogo.github.io/cvss/examples/basic) - 简单的使用示例

### 深入学习
- [CVSS 包详解](https://scagogogo.github.io/cvss/api/cvss/) - 核心功能介绍
- [解析器使用](https://scagogogo.github.io/cvss/api/parser/) - 字符串解析
- [向量分析](https://scagogogo.github.io/cvss/api/cvss/distance) - 高级分析功能

### 实用示例
- [JSON 处理](https://scagogogo.github.io/cvss/examples/json) - 数据序列化
- [批量处理](https://scagogogo.github.io/cvss/examples/parsing) - 批量解析向量
- [相似度分析](https://scagogogo.github.io/cvss/examples/distance) - 向量比较

## 贡献

欢迎贡献代码、报告问题和提出改进建议！请查看我们的：

- [GitHub Issues](https://github.com/scagogogo/cvss/issues) - 报告问题或建议
- [贡献指南](https://scagogogo.github.io/cvss/contributing) - 了解如何贡献代码
- [开发文档](https://scagogogo.github.io/cvss/development) - 开发环境设置

## 许可证

本项目基于 MIT 许可证 - 详情请参见 [LICENSE](LICENSE) 文件。

## 致谢

- [CVSS v3.1 规范](https://www.first.org/cvss/v3.1/specification-document)
- [CVSS v3.0 规范](https://www.first.org/cvss/v3.0/specification-document)
