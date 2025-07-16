# 快速开始

本指南将帮助你在 5 分钟内开始使用 CVSS Parser。

## 安装

使用 Go modules 安装 CVSS Parser：

```bash
go get github.com/scagogogo/cvss
```

## 基础用法

### 1. 解析 CVSS 向量

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cvss-parser/pkg/parser"
)

func main() {
    // 创建解析器
    p := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    
    // 解析向量
    cvssVector, err := p.Parse()
    if err != nil {
        log.Fatalf("解析失败: %v", err)
    }
    
    fmt.Printf("解析成功: %s\n", cvssVector.String())
}
```

### 2. 计算 CVSS 评分

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cvss-parser/pkg/parser"
    "github.com/scagogogo/cvss-parser/pkg/cvss"
)

func main() {
    // 解析向量
    p := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    cvssVector, err := p.Parse()
    if err != nil {
        log.Fatalf("解析失败: %v", err)
    }
    
    // 创建计算器
    calculator := cvss.NewCalculator(cvssVector)
    
    // 计算评分
    score, err := calculator.Calculate()
    if err != nil {
        log.Fatalf("计算失败: %v", err)
    }
    
    fmt.Printf("CVSS 评分: %.1f\n", score)
    fmt.Printf("严重性级别: %s\n", calculator.GetSeverityRating(score))
}
```

### 3. JSON 输出

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"
    
    "github.com/scagogogo/cvss-parser/pkg/parser"
)

func main() {
    // 解析向量
    p := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    cvssVector, err := p.Parse()
    if err != nil {
        log.Fatalf("解析失败: %v", err)
    }
    
    // 转换为 JSON
    jsonData, err := json.MarshalIndent(cvssVector, "", "  ")
    if err != nil {
        log.Fatalf("JSON 序列化失败: %v", err)
    }
    
    fmt.Println(string(jsonData))
}
```

## 常见用例

### 批量处理向量

```go
func processVectors(vectors []string) {
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

### 向量比较

```go
func compareVectors(vector1Str, vector2Str string) {
    // 解析两个向量
    p1 := parser.NewCvss3xParser(vector1Str)
    v1, err := p1.Parse()
    if err != nil {
        log.Fatalf("解析向量1失败: %v", err)
    }
    
    p2 := parser.NewCvss3xParser(vector2Str)
    v2, err := p2.Parse()
    if err != nil {
        log.Fatalf("解析向量2失败: %v", err)
    }
    
    // 计算距离
    distCalc := cvss.NewDistanceCalculator(v1, v2)
    distance := distCalc.EuclideanDistance()
    
    fmt.Printf("向量距离: %.3f\n", distance)
}
```

## 错误处理

CVSS Parser 提供详细的错误信息：

```go
p := parser.NewCvss3xParser("INVALID:VECTOR")
_, err := p.Parse()
if err != nil {
    // 错误信息会包含具体的解析位置和原因
    fmt.Printf("解析错误: %v\n", err)
}
```

常见错误类型：
- **语法错误**: 向量字符串格式不正确
- **版本错误**: 不支持的 CVSS 版本
- **指标错误**: 无效的指标值
- **计算错误**: 缺少必需的指标

## 最佳实践

### 1. 错误处理
始终检查错误返回值：

```go
if err != nil {
    return fmt.Errorf("操作失败: %w", err)
}
```

### 2. 资源管理
解析器和计算器都是轻量级的，可以按需创建：

```go
// 每次解析创建新的解析器
p := parser.NewCvss3xParser(vectorString)
```

### 3. 并发使用
计算器是并发安全的，可以在多个 goroutine 中使用：

```go
go func() {
    calculator := cvss.NewCalculator(cvssVector)
    score, _ := calculator.Calculate()
    // 处理结果
}()
```

## 下一步

现在你已经掌握了基础用法，可以：

- 📖 [查看完整 API 文档](/api/cvss/)
- 🔍 [浏览更多示例](/examples/)
- 🛠️ [了解高级功能](/api/cvss/distance)

## 需要帮助？

- 查看 [示例代码](/examples/)
- 阅读 [API 文档](/api/)
- 访问 [GitHub 仓库](https://github.com/scagogogo/cvss)
