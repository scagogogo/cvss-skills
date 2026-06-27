# DistanceCalculator - 向量距离计算器

`DistanceCalculator` 用于计算两个 CVSS 向量之间的距离。它支持多种距离算法，可用于向量相似性分析和聚类。

## 接口定义

```go
type DistanceCalculator interface {
    EuclideanDistance() float64
    ManhattanDistance() float64
    ChebyshevDistance() float64
    CosineSimilarity() float64
    JaccardSimilarity() float64
}
```

## 创建计算器

### NewDistanceCalculator

```go
func NewDistanceCalculator(vector1, vector2 *Cvss3x) DistanceCalculator
```

为两个 CVSS 向量创建新的距离计算器。

**参数:**
- `vector1`: 第一个 CVSS 向量
- `vector2`: 第二个 CVSS 向量

**返回值:**
- `DistanceCalculator`: 距离计算器实例

**示例:**
```go
calc := cvss.NewDistanceCalculator(vector1, vector2)
```

## 距离算法

### EuclideanDistance

```go
func (d *DistanceCalculator) EuclideanDistance() float64
```

计算两个向量之间的欧几里得距离。

**公式:**
```
distance = √(Σ(xi - yi)²)
```

其中 xi 和 yi 是两个向量在第 i 个维度上的值。

**返回值:**
- `float64`: 欧几里得距离值 (0.0 到 ∞)

**示例:**
```go
distance := calc.EuclideanDistance()
fmt.Printf("欧几里得距离: %.3f\n", distance)
```

**用途:**
- 向量相似性分析
- 聚类算法
- 异常检测

### ManhattanDistance

```go
func (d *DistanceCalculator) ManhattanDistance() float64
```

计算两个向量之间的曼哈顿距离（也称为城市街区距离）。

**公式:**
```
distance = Σ|xi - yi|
```

**返回值:**
- `float64`: 曼哈顿距离值 (0.0 到 ∞)

**示例:**
```go
distance := calc.ManhattanDistance()
fmt.Printf("曼哈顿距离: %.3f\n", distance)
```

**特点:**
- 对异常值不敏感
- 计算效率高
- 适用于高维数据

### ChebyshevDistance

```go
func (d *DistanceCalculator) ChebyshevDistance() float64
```

计算两个向量之间的切比雪夫距离（也称为无穷范数距离）。

**公式:**
```
distance = max(|xi - yi|)
```

**返回值:**
- `float64`: 切比雪夫距离值 (0.0 到 ∞)

**示例:**
```go
distance := calc.ChebyshevDistance()
fmt.Printf("切比雪夫距离: %.3f\n", distance)
```

**应用场景:**
- 最大差异分析
- 游戏AI路径规划
- 图像处理

## 相似性度量

### CosineSimilarity

```go
func (d *DistanceCalculator) CosineSimilarity() float64
```

计算两个向量之间的余弦相似度。

**公式:**
```
similarity = (A · B) / (||A|| × ||B||)
```

其中 A · B 是向量点积，||A|| 和 ||B|| 是向量的欧几里得范数。

**返回值:**
- `float64`: 余弦相似度值 (-1.0 到 1.0)
  - 1.0: 完全相同
  - 0.0: 正交（无关）
  - -1.0: 完全相反

**示例:**
```go
similarity := calc.CosineSimilarity()
fmt.Printf("余弦相似度: %.3f\n", similarity)

if similarity > 0.9 {
    fmt.Println("向量非常相似")
} else if similarity > 0.7 {
    fmt.Println("向量相似")
} else if similarity > 0.3 {
    fmt.Println("向量有一定相似性")
} else {
    fmt.Println("向量差异较大")
}
```

**优势:**
- 不受向量大小影响
- 适用于高维稀疏数据
- 广泛用于文本分析和推荐系统

### JaccardSimilarity

```go
func (d *DistanceCalculator) JaccardSimilarity() float64
```

计算两个向量之间的雅卡德相似度。

**公式:**
```
similarity = |A ∩ B| / |A ∪ B|
```

**返回值:**
- `float64`: 雅卡德相似度值 (0.0 到 1.0)
  - 1.0: 完全相同
  - 0.0: 完全不同

**示例:**
```go
similarity := calc.JaccardSimilarity()
fmt.Printf("雅卡德相似度: %.3f\n", similarity)
```

**应用:**
- 集合相似性分析
- 二进制特征比较
- 推荐系统

## 实际应用示例

### 基本距离计算

```go
package main

import (
    "fmt"
    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    // 解析两个 CVSS 向量
    vector1Str := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    vector2Str := "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"

    parser1 := parser.NewCvss3xParser(vector1Str)
    vector1, _ := parser1.Parse()

    parser2 := parser.NewCvss3xParser(vector2Str)
    vector2, _ := parser2.Parse()

    // 创建距离计算器
    calc := cvss.NewDistanceCalculator(vector1, vector2)

    // 计算各种距离
    fmt.Printf("欧几里得距离: %.3f\n", calc.EuclideanDistance())
    fmt.Printf("曼哈顿距离: %.3f\n", calc.ManhattanDistance())
    fmt.Printf("切比雪夫距离: %.3f\n", calc.ChebyshevDistance())
    fmt.Printf("余弦相似度: %.3f\n", calc.CosineSimilarity())
    fmt.Printf("雅卡德相似度: %.3f\n", calc.JaccardSimilarity())
}
```

### 向量聚类分析

```go
func clusterVectors(vectors []*cvss.Cvss3x, threshold float64) [][]int {
    var clusters [][]int
    used := make([]bool, len(vectors))

    for i, vector1 := range vectors {
        if used[i] {
            continue
        }

        cluster := []int{i}
        used[i] = true

        for j, vector2 := range vectors {
            if i == j || used[j] {
                continue
            }

            calc := cvss.NewDistanceCalculator(vector1, vector2)
            distance := calc.EuclideanDistance()

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

### 相似性分析

```go
func analyzeSimilarity(v1, v2 *cvss.Cvss3x) {
    calc := cvss.NewDistanceCalculator(v1, v2)
    
    euclidean := calc.EuclideanDistance()
    cosine := calc.CosineSimilarity()
    
    fmt.Printf("向量1: %s\n", v1.String())
    fmt.Printf("向量2: %s\n", v2.String())
    fmt.Printf("欧几里得距离: %.3f\n", euclidean)
    fmt.Printf("余弦相似度: %.3f\n", cosine)
    
    // 相似性判断
    if cosine > 0.9 {
        fmt.Println("结论: 向量非常相似")
    } else if cosine > 0.7 {
        fmt.Println("结论: 向量相似")
    } else if cosine > 0.3 {
        fmt.Println("结论: 向量有一定相似性")
    } else {
        fmt.Println("结论: 向量差异较大")
    }
}
```

## 性能优化

### 批量计算优化

```go
type BatchDistanceCalculator struct {
    vectors []*cvss.Cvss3x
    cache   map[string]float64
    mutex   sync.RWMutex
}

func NewBatchDistanceCalculator(vectors []*cvss.Cvss3x) *BatchDistanceCalculator {
    return &BatchDistanceCalculator{
        vectors: vectors,
        cache:   make(map[string]float64),
    }
}

func (b *BatchDistanceCalculator) GetDistance(i, j int, algorithm string) float64 {
    if i == j {
        return 0.0
    }

    // 确保一致的缓存键顺序
    if i > j {
        i, j = j, i
    }

    key := fmt.Sprintf("%d-%d-%s", i, j, algorithm)

    b.mutex.RLock()
    if distance, exists := b.cache[key]; exists {
        b.mutex.RUnlock()
        return distance
    }
    b.mutex.RUnlock()

    calc := cvss.NewDistanceCalculator(b.vectors[i], b.vectors[j])

    var distance float64
    switch algorithm {
    case "euclidean":
        distance = calc.EuclideanDistance()
    case "manhattan":
        distance = calc.ManhattanDistance()
    case "cosine":
        distance = calc.CosineSimilarity()
    default:
        distance = calc.EuclideanDistance()
    }

    b.mutex.Lock()
    b.cache[key] = distance
    b.mutex.Unlock()

    return distance
}
```

## 最佳实践

### 算法选择指南

1. **欧几里得距离**
   - 适用于连续数值特征
   - 对异常值敏感
   - 常用于聚类分析

2. **曼哈顿距离**
   - 适用于高维数据
   - 对异常值不敏感
   - 计算效率高

3. **余弦相似度**
   - 适用于方向性比较
   - 不受向量大小影响
   - 推荐用于文本和稀疏数据

4. **雅卡德相似度**
   - 适用于二进制特征
   - 集合相似性分析
   - 简单直观

### 错误处理

```go
func safeDistanceCalculation(v1, v2 *cvss.Cvss3x) (float64, error) {
    if v1 == nil || v2 == nil {
        return 0, fmt.Errorf("向量不能为空")
    }

    if !v1.IsValid() || !v2.IsValid() {
        return 0, fmt.Errorf("向量无效")
    }

    calc := cvss.NewDistanceCalculator(v1, v2)
    return calc.EuclideanDistance(), nil
}
```

## 相关文档

- [CVSS 数据结构](/zh/api/cvss/cvss3x) - 了解 CVSS 向量结构
- [距离计算示例](/zh/examples/distance) - 详细使用示例
- [向量比较](/zh/examples/comparison) - 向量比较方法
