# 示例

这里提供了 CVSS Parser 的完整示例集合，涵盖了从基础用法到高级功能的各种使用场景。

## 示例概览

### 🚀 入门示例
- [基础用法](/zh/examples/basic) - 最简单的解析和计算示例
- [解析向量](/zh/examples/parsing) - 各种格式的向量解析

### 📊 功能示例
- [JSON 输出](/zh/examples/json) - JSON 序列化和反序列化
- [时间指标](/zh/examples/temporal) - 时间指标的使用和影响
- [环境指标](/zh/examples/environmental) - 环境指标的配置和计算

### 🔍 分析示例
- [距离计算](/zh/examples/distance) - 向量距离和相似度分析
- [向量比较](/zh/examples/comparison) - 多种比较方法
- [严重性级别](/zh/examples/severity) - 严重性评级和分类

### 🛠️ 高级示例
- [边缘情况](/zh/examples/edge-cases) - 错误处理和边缘情况

## 快速开始

如果你是第一次使用 CVSS Parser，建议按以下顺序学习：

1. **[基础用法](/zh/examples/basic)** - 了解基本的解析和计算流程
2. **[解析向量](/zh/examples/parsing)** - 学习如何解析不同格式的向量
3. **[JSON 输出](/zh/examples/json)** - 掌握数据序列化和存储
4. **[距离计算](/zh/examples/distance)** - 探索向量分析功能

## 运行示例

所有示例都可以直接运行。首先克隆项目：

```bash
git clone https://github.com/scagogogo/cvss.git
cd cvss
```

然后运行任何示例：

```bash
# 运行基础示例
go run examples/01_basic/main.go

# 运行JSON示例
go run examples/03_json/main.go

# 运行距离计算示例
go run examples/06_distance/main.go
```

## 示例代码结构

每个示例都包含：

- **完整的可运行代码** - 可以直接复制和运行
- **详细的注释** - 解释每个步骤的作用
- **输出示例** - 展示预期的运行结果
- **相关概念** - 链接到相关的API文档

## 常见用例

### 1. 基本解析和计算

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cvss-parser/pkg/parser"
    "github.com/scagogogo/cvss-parser/pkg/cvss"
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

### 2. 批量处理

```go
func processBatch(vectors []string) {
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
        
        fmt.Printf("%s -> %.1f (%s)\n", 
            vectorStr, score, calculator.GetSeverityRating(score))
    }
}
```

### 3. 向量比较

```go
func compareVectors(v1Str, v2Str string) {
    // 解析两个向量
    p1 := parser.NewCvss3xParser(v1Str)
    vector1, _ := p1.Parse()
    
    p2 := parser.NewCvss3xParser(v2Str)
    vector2, _ := p2.Parse()
    
    // 计算距离
    distCalc := cvss.NewDistanceCalculator(vector1, vector2)
    distance := distCalc.EuclideanDistance()
    
    fmt.Printf("向量距离: %.3f\n", distance)
}
```

## 测试数据

以下是一些用于测试的 CVSS 向量：

### 基础向量
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H    # 高危网络攻击
CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L    # 低危本地攻击
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H    # 严重网络攻击
```

### 包含时间指标
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C
CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H/E:P/RL:T/RC:R
```

### 包含环境指标
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAV:L/MAC:H/MPR:H
```

## 性能测试

运行性能测试：

```bash
# 运行基准测试
go test -bench=. ./pkg/parser
go test -bench=. ./pkg/cvss

# 运行内存分析
go test -bench=. -memprofile=mem.prof ./pkg/parser
go tool pprof mem.prof
```

## 贡献示例

如果你有好的示例想要分享：

1. 在 `examples/` 目录下创建新的示例
2. 确保代码可以直接运行
3. 添加详细的注释和说明
4. 更新本文档的索引
5. 提交 Pull Request

## 获取帮助

如果在运行示例时遇到问题：

- 查看 [API 文档](/zh/api/)
- 检查 [GitHub Issues](https://github.com/scagogogo/cvss/issues)
- 参考 [最佳实践](/zh/api/getting-started)

## 下一步

选择一个感兴趣的示例开始学习：

- 🚀 [基础用法](/zh/examples/basic) - 快速上手
- 📊 [JSON 输出](/zh/examples/json) - 数据处理
- 🔍 [距离计算](/zh/examples/distance) - 高级分析
- 🛠️ [边缘情况](/zh/examples/edge-cases) - 错误处理
