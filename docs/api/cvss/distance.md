# DistanceCalculator - 向量距离计算器

`DistanceCalculator` 用于计算两个 CVSS 向量之间的距离，支持多种距离算法，可用于向量相似度分析和聚类。

## 类型定义

```go
type DistanceCalculator struct {
    vector1 *Cvss3x  // 第一个向量
    vector2 *Cvss3x  // 第二个向量
}
```

## 构造函数

### NewDistanceCalculator

```go
func NewDistanceCalculator(vector1, vector2 *Cvss3x) *DistanceCalculator
```

创建一个新的距离计算器。

**参数：**
- `vector1` - 第一个 CVSS 向量
- `vector2` - 第二个 CVSS 向量

**返回值：**
- `*DistanceCalculator` - 距离计算器实例

**示例：**
```go
distCalc := cvss.NewDistanceCalculator(vector1, vector2)
```

## 距离算法

### EuclideanDistance

```go
func (dc *DistanceCalculator) EuclideanDistance() float64
```

计算两个向量之间的欧几里得距离（直线距离）。

**公式：**
```
d = √(Σ(xi - yi)²)
```

其中 xi 和 yi 是两个向量在第 i 个维度上的分数值。

**返回值：**
- `float64` - 欧几里得距离值

**示例：**
```go
distance := distCalc.EuclideanDistance()
fmt.Printf("欧几里得距离: %.3f\n", distance)
```

### ManhattanDistance

```go
func (dc *DistanceCalculator) ManhattanDistance() float64
```

计算两个向量之间的曼哈顿距离（城市街区距离）。

**公式：**
```
d = Σ|xi - yi|
```

**返回值：**
- `float64` - 曼哈顿距离值

**示例：**
```go
distance := distCalc.ManhattanDistance()
fmt.Printf("曼哈顿距离: %.3f\n", distance)
```

### ChebyshevDistance

```go
func (dc *DistanceCalculator) ChebyshevDistance() float64
```

计算两个向量之间的切比雪夫距离（最大距离）。

**公式：**
```
d = max(|xi - yi|)
```

**返回值：**
- `float64` - 切比雪夫距离值

**示例：**
```go
distance := distCalc.ChebyshevDistance()
fmt.Printf("切比雪夫距离: %.3f\n", distance)
```

### CosineSimilarity

```go
func (dc *DistanceCalculator) CosineSimilarity() float64
```

计算两个向量之间的余弦相似度。

**公式：**
```
similarity = (A·B) / (||A|| × ||B||)
```

**返回值：**
- `float64` - 余弦相似度值 (0-1，1表示完全相似)

**示例：**
```go
similarity := distCalc.CosineSimilarity()
fmt.Printf("余弦相似度: %.3f\n", similarity)
```

## 距离计算维度

距离计算基于以下 CVSS 指标的分数值：

### 基础指标 (8个维度)
1. 攻击向量 (AV)
2. 攻击复杂性 (AC)
3. 所需权限 (PR)
4. 用户交互 (UI)
5. 影响范围 (S)
6. 机密性影响 (C)
7. 完整性影响 (I)
8. 可用性影响 (A)

### 时间指标 (3个维度)
9. 漏洞利用代码成熟度 (E)
10. 修复级别 (RL)
11. 报告可信度 (RC)

### 环境指标 (11个维度)
12. 机密性需求 (CR)
13. 完整性需求 (IR)
14. 可用性需求 (AR)
15. 修改的攻击向量 (MAV)
16. 修改的攻击复杂性 (MAC)
17. 修改的所需权限 (MPR)
18. 修改的用户交互 (MUI)
19. 修改的影响范围 (MS)
20. 修改的机密性影响 (MC)
21. 修改的完整性影响 (MI)
22. 修改的可用性影响 (MA)

## 完整示例

### 基本距离计算

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cvss-parser/pkg/parser"
    "github.com/scagogogo/cvss-parser/pkg/cvss"
)

func main() {
    // 解析两个向量
    p1 := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    vector1, err := p1.Parse()
    if err != nil {
        log.Fatalf("解析向量1失败: %v", err)
    }
    
    p2 := parser.NewCvss3xParser("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:L")
    vector2, err := p2.Parse()
    if err != nil {
        log.Fatalf("解析向量2失败: %v", err)
    }
    
    // 创建距离计算器
    distCalc := cvss.NewDistanceCalculator(vector1, vector2)
    
    // 计算各种距离
    euclidean := distCalc.EuclideanDistance()
    manhattan := distCalc.ManhattanDistance()
    chebyshev := distCalc.ChebyshevDistance()
    cosine := distCalc.CosineSimilarity()
    
    fmt.Printf("欧几里得距离: %.3f\n", euclidean)
    fmt.Printf("曼哈顿距离: %.3f\n", manhattan)
    fmt.Printf("切比雪夫距离: %.3f\n", chebyshev)
    fmt.Printf("余弦相似度: %.3f\n", cosine)
}
```

### 向量聚类分析

```go
func clusterVectors(vectors []*cvss.Cvss3x, threshold float64) [][]int {
    var clusters [][]int
    used := make([]bool, len(vectors))
    
    for i, v1 := range vectors {
        if used[i] {
            continue
        }
        
        cluster := []int{i}
        used[i] = true
        
        for j, v2 := range vectors {
            if i == j || used[j] {
                continue
            }
            
            distCalc := cvss.NewDistanceCalculator(v1, v2)
            distance := distCalc.EuclideanDistance()
            
            if distance <= threshold {
                cluster = append(cluster, j)
                used[j] = true
            }
        }
        
        clusters = append(clusters, cluster)
    }
    
    return clusters
}
```

### 最相似向量查找

```go
func findMostSimilar(target *cvss.Cvss3x, candidates []*cvss.Cvss3x) (*cvss.Cvss3x, float64) {
    var mostSimilar *cvss.Cvss3x
    var maxSimilarity float64
    
    for _, candidate := range candidates {
        distCalc := cvss.NewDistanceCalculator(target, candidate)
        similarity := distCalc.CosineSimilarity()
        
        if similarity > maxSimilarity {
            maxSimilarity = similarity
            mostSimilar = candidate
        }
    }
    
    return mostSimilar, maxSimilarity
}
```

### 距离矩阵计算

```go
func calculateDistanceMatrix(vectors []*cvss.Cvss3x) [][]float64 {
    n := len(vectors)
    matrix := make([][]float64, n)
    
    for i := range matrix {
        matrix[i] = make([]float64, n)
    }
    
    for i := 0; i < n; i++ {
        for j := i; j < n; j++ {
            if i == j {
                matrix[i][j] = 0.0
            } else {
                distCalc := cvss.NewDistanceCalculator(vectors[i], vectors[j])
                distance := distCalc.EuclideanDistance()
                matrix[i][j] = distance
                matrix[j][i] = distance // 对称矩阵
            }
        }
    }
    
    return matrix
}
```

## 应用场景

### 1. 漏洞相似度分析
```go
// 找出与已知漏洞相似的其他漏洞
func findSimilarVulnerabilities(knownVuln *cvss.Cvss3x, database []*cvss.Cvss3x, threshold float64) []*cvss.Cvss3x {
    var similar []*cvss.Cvss3x
    
    for _, vuln := range database {
        distCalc := cvss.NewDistanceCalculator(knownVuln, vuln)
        distance := distCalc.EuclideanDistance()
        
        if distance <= threshold {
            similar = append(similar, vuln)
        }
    }
    
    return similar
}
```

### 2. 风险评估优化
```go
// 基于历史数据优化风险评估
func optimizeRiskAssessment(currentVector *cvss.Cvss3x, historicalData []*cvss.Cvss3x) float64 {
    totalWeight := 0.0
    weightedScore := 0.0
    
    for _, historical := range historicalData {
        distCalc := cvss.NewDistanceCalculator(currentVector, historical)
        similarity := distCalc.CosineSimilarity()
        
        if similarity > 0.8 { // 高相似度阈值
            calculator := cvss.NewCalculator(historical)
            score, _ := calculator.Calculate()
            
            weightedScore += score * similarity
            totalWeight += similarity
        }
    }
    
    if totalWeight > 0 {
        return weightedScore / totalWeight
    }
    
    // 如果没有相似的历史数据，使用当前向量计算
    calculator := cvss.NewCalculator(currentVector)
    score, _ := calculator.Calculate()
    return score
}
```

## 性能考虑

### 计算复杂度
- **欧几里得距离**: O(n)，其中 n 是向量维度数
- **曼哈顿距离**: O(n)
- **切比雪夫距离**: O(n)
- **余弦相似度**: O(n)

### 内存使用
- 距离计算器本身占用内存很少
- 可以重复使用同一个计算器实例
- 支持并发计算

### 优化建议
```go
// 批量计算时重用计算器
distCalc := cvss.NewDistanceCalculator(nil, nil)
for i := 0; i < len(vectors); i++ {
    for j := i+1; j < len(vectors); j++ {
        distCalc.vector1 = vectors[i]
        distCalc.vector2 = vectors[j]
        distance := distCalc.EuclideanDistance()
        // 处理距离结果
    }
}
```

## 最佳实践

### 1. 选择合适的距离算法
- **欧几里得距离**: 适用于一般的相似度分析
- **曼哈顿距离**: 适用于对异常值不敏感的场景
- **切比雪夫距离**: 适用于关注最大差异的场景
- **余弦相似度**: 适用于关注向量方向而非大小的场景

### 2. 处理缺失指标
```go
// 检查向量完整性
if vector1.Cvss3xBase == nil || vector2.Cvss3xBase == nil {
    return 0.0 // 或其他默认值
}
```

### 3. 设置合理的阈值
```go
const (
    HighSimilarityThreshold   = 0.2  // 高相似度
    MediumSimilarityThreshold = 0.5  // 中等相似度
    LowSimilarityThreshold    = 1.0  // 低相似度
)
```

## 相关文档

- [Cvss3x 数据结构](/api/cvss/cvss3x)
- [Calculator 评分计算](/api/cvss/calculator)
- [向量比较示例](/examples/comparison)
