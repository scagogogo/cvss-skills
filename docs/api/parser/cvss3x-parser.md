# Cvss3xParser - CVSS 3.x 解析器

`Cvss3xParser` 是专门用于解析 CVSS 3.x 向量字符串的解析器，支持 CVSS 3.0 和 3.1 格式。

## 类型定义

```go
type Cvss3xParser struct {
    cvss3xStr   string        // 原始CVSS字符串
    csvv3x      *cvss.Cvss3x  // 解析结果
    cvss3xRunes []rune        // 字符串的rune表示
    i           int           // 当前解析位置
}
```

## 构造函数

### NewCvss3xParser

```go
func NewCvss3xParser(cvss3xStr string) *Cvss3xParser
```

创建一个新的 CVSS 3.x 解析器实例。

**参数：**
- `cvss3xStr` - 要解析的 CVSS 向量字符串

**返回值：**
- `*Cvss3xParser` - 解析器实例

**示例：**
```go
parser := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
```

## 主要方法

### Parse

```go
func (x *Cvss3xParser) Parse() (*cvss.Cvss3x, error)
```

解析 CVSS 向量字符串并返回结构化的 CVSS 对象。

**返回值：**
- `*cvss.Cvss3x` - 解析得到的 CVSS 向量对象
- `error` - 解析过程中的错误

**解析流程：**
1. 读取并验证魔术头 "CVSS"
2. 解析版本号（主版本号和次版本号）
3. 解析基础指标（8个必需指标）
4. 解析时间指标（可选）
5. 解析环境指标（可选）

**示例：**
```go
cvssVector, err := parser.Parse()
if err != nil {
    log.Fatalf("解析失败: %v", err)
}
fmt.Printf("解析成功: %s\n", cvssVector.String())
```

## 支持的向量格式

### 基础向量（仅包含基础指标）
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

### 包含时间指标的向量
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C
```

### 包含环境指标的向量
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H
```

### 完整向量（包含所有指标）
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C/CR:H/IR:H/AR:H/MAV:L/MAC:H/MPR:L/MUI:R/MS:C/MC:H/MI:H/MA:H
```

## 指标映射

### 基础指标

| 指标 | 简写 | 可能值 | 对应类型 |
|------|------|--------|----------|
| 攻击向量 | AV | N, A, L, P | AttackVector* |
| 攻击复杂性 | AC | L, H | AttackComplexity* |
| 所需权限 | PR | N, L, H | PrivilegesRequired* |
| 用户交互 | UI | N, R | UserInteraction* |
| 影响范围 | S | U, C | Scope* |
| 机密性影响 | C | N, L, H | Confidentiality* |
| 完整性影响 | I | N, L, H | Integrity* |
| 可用性影响 | A | N, L, H | Availability* |

### 时间指标

| 指标 | 简写 | 可能值 | 对应类型 |
|------|------|--------|----------|
| 漏洞利用代码成熟度 | E | X, U, P, F, H | ExploitCodeMaturity* |
| 修复级别 | RL | X, O, T, W, U | RemediationLevel* |
| 报告可信度 | RC | X, U, R, C | ReportConfidence* |

### 环境指标

| 指标 | 简写 | 可能值 | 对应类型 |
|------|------|--------|----------|
| 机密性需求 | CR | X, L, M, H | ConfidentialityRequirement* |
| 完整性需求 | IR | X, L, M, H | IntegrityRequirement* |
| 可用性需求 | AR | X, L, M, H | AvailabilityRequirement* |
| 修改的攻击向量 | MAV | X, N, A, L, P | AttackVector* |
| 修改的攻击复杂性 | MAC | X, L, H | AttackComplexity* |
| 修改的所需权限 | MPR | X, N, L, H | PrivilegesRequired* |
| 修改的用户交互 | MUI | X, N, R | UserInteraction* |
| 修改的影响范围 | MS | X, U, C | Scope* |
| 修改的机密性影响 | MC | X, N, L, H | Confidentiality* |
| 修改的完整性影响 | MI | X, N, L, H | Integrity* |
| 修改的可用性影响 | MA | X, N, L, H | Availability* |

## 错误处理

### 常见错误类型

#### 1. 魔术头错误
```go
// 错误的魔术头
parser := parser.NewCvss3xParser("INVALID:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
_, err := parser.Parse()
// 返回: ErrParserMagicHead
```

#### 2. 版本号错误
```go
// 不支持的版本
parser := parser.NewCvss3xParser("CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
_, err := parser.Parse()
// 返回: "invalid major version" 或 "major version must be followed by '.'"
```

#### 3. 语法错误
```go
// 缺少分隔符
parser := parser.NewCvss3xParser("CVSS:3.1AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
_, err := parser.Parse()
// 返回: "invalid syntax"
```

#### 4. 指标错误
```go
// 无效的指标值
parser := parser.NewCvss3xParser("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
_, err := parser.Parse()
// 返回: "unknown vector value"
```

#### 5. 缺少必需指标
```go
// 缺少基础指标
parser := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N")
_, err := parser.Parse()
// 返回: "User Interaction can not empty"
```

## 完整示例

### 基本解析示例

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cvss-parser/pkg/parser"
    "github.com/scagogogo/cvss-parser/pkg/cvss"
)

func main() {
    vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    // 创建解析器
    p := parser.NewCvss3xParser(vectorStr)
    
    // 解析向量
    cvssVector, err := p.Parse()
    if err != nil {
        log.Fatalf("解析失败: %v", err)
    }
    
    // 验证解析结果
    if err := cvssVector.Check(); err != nil {
        log.Fatalf("向量验证失败: %v", err)
    }
    
    // 计算评分
    calculator := cvss.NewCalculator(cvssVector)
    score, err := calculator.Calculate()
    if err != nil {
        log.Fatalf("计算失败: %v", err)
    }
    
    fmt.Printf("原始向量: %s\n", vectorStr)
    fmt.Printf("解析结果: %s\n", cvssVector.String())
    fmt.Printf("CVSS评分: %.1f\n", score)
    fmt.Printf("严重性: %s\n", calculator.GetSeverityRating(score))
}
```

### 批量解析示例

```go
func parseBatch(vectors []string) {
    for i, vectorStr := range vectors {
        fmt.Printf("解析向量 %d: %s\n", i+1, vectorStr)
        
        p := parser.NewCvss3xParser(vectorStr)
        cvssVector, err := p.Parse()
        if err != nil {
            fmt.Printf("  ❌ 解析失败: %v\n", err)
            continue
        }
        
        calculator := cvss.NewCalculator(cvssVector)
        score, err := calculator.Calculate()
        if err != nil {
            fmt.Printf("  ❌ 计算失败: %v\n", err)
            continue
        }
        
        fmt.Printf("  ✅ 评分: %.1f (%s)\n", score, calculator.GetSeverityRating(score))
    }
}
```

### 错误处理示例

```go
func parseWithDetailedErrorHandling(vectorStr string) (*cvss.Cvss3x, error) {
    p := parser.NewCvss3xParser(vectorStr)
    cvssVector, err := p.Parse()
    if err != nil {
        // 根据错误类型提供详细信息
        switch {
        case err == parser.ErrParserMagicHead:
            return nil, fmt.Errorf("CVSS向量必须以'CVSS:'开头")
        case strings.Contains(err.Error(), "major version"):
            return nil, fmt.Errorf("不支持的CVSS版本，仅支持3.0和3.1")
        case strings.Contains(err.Error(), "can not empty"):
            return nil, fmt.Errorf("缺少必需的基础指标: %v", err)
        case strings.Contains(err.Error(), "unknown vector"):
            return nil, fmt.Errorf("无效的指标值: %v", err)
        default:
            return nil, fmt.Errorf("解析错误: %v", err)
        }
    }
    
    return cvssVector, nil
}
```

### 性能测试示例

```go
func benchmarkParsing() {
    vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C"
    
    start := time.Now()
    for i := 0; i < 10000; i++ {
        p := parser.NewCvss3xParser(vectorStr)
        _, err := p.Parse()
        if err != nil {
            log.Fatalf("解析失败: %v", err)
        }
    }
    duration := time.Since(start)
    
    fmt.Printf("解析10000次耗时: %v\n", duration)
    fmt.Printf("平均每次: %v\n", duration/10000)
}
```

## 内部实现细节

### 解析状态机

解析器使用状态机模式进行解析：

```go
// 解析流程
1. readMagicHead()     // 读取 "CVSS"
2. readVersion()       // 读取版本号
3. readBaseMetrics()   // 读取基础指标
4. readTemporalMetrics() // 读取时间指标（可选）
5. readEnvironmentalMetrics() // 读取环境指标（可选）
```

### 字符串处理

```go
// 使用 rune 数组处理 Unicode 字符
cvss3xRunes []rune
i           int  // 当前位置指针

// 读取下一个字符
func (x *Cvss3xParser) read() rune {
    if x.i >= len(x.cvss3xRunes) {
        return 0
    }
    c := x.cvss3xRunes[x.i]
    x.i++
    return c
}
```

## 最佳实践

### 1. 输入验证
```go
func validateInput(vectorStr string) error {
    if strings.TrimSpace(vectorStr) == "" {
        return fmt.Errorf("CVSS向量字符串不能为空")
    }
    if len(vectorStr) > 1000 {
        return fmt.Errorf("CVSS向量字符串过长")
    }
    return nil
}
```

### 2. 错误记录
```go
func parseWithLogging(vectorStr string) (*cvss.Cvss3x, error) {
    log.Printf("开始解析CVSS向量: %s", vectorStr)
    
    p := parser.NewCvss3xParser(vectorStr)
    cvssVector, err := p.Parse()
    if err != nil {
        log.Printf("解析失败: %v", err)
        return nil, err
    }
    
    log.Printf("解析成功: %s", cvssVector.String())
    return cvssVector, nil
}
```

### 3. 缓存解析结果
```go
var parseCache = make(map[string]*cvss.Cvss3x)
var cacheMutex sync.RWMutex

func parseWithCache(vectorStr string) (*cvss.Cvss3x, error) {
    cacheMutex.RLock()
    if cached, exists := parseCache[vectorStr]; exists {
        cacheMutex.RUnlock()
        return cached, nil
    }
    cacheMutex.RUnlock()
    
    p := parser.NewCvss3xParser(vectorStr)
    cvssVector, err := p.Parse()
    if err != nil {
        return nil, err
    }
    
    cacheMutex.Lock()
    parseCache[vectorStr] = cvssVector
    cacheMutex.Unlock()
    
    return cvssVector, nil
}
```

## 相关文档

- [parser 包概述](/api/parser/)
- [Cvss3x 数据结构](/api/cvss/cvss3x)
- [解析示例](/examples/parsing)
