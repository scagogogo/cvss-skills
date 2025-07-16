# JSON 支持

CVSS Parser 提供完整的 JSON 序列化和反序列化支持，方便数据存储、传输和与其他系统集成。

## 功能概述

- **序列化**: 将 CVSS 对象转换为 JSON 格式
- **反序列化**: 从 JSON 数据重建 CVSS 对象
- **完整性保持**: 保留所有指标信息和元数据
- **格式化输出**: 支持美化的 JSON 输出

## 基本用法

### JSON 序列化

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"
    
    "github.com/scagogogo/cvss-parser/pkg/parser"
)

func main() {
    // 解析 CVSS 向量
    p := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    cvssVector, err := p.Parse()
    if err != nil {
        log.Fatalf("解析失败: %v", err)
    }
    
    // 序列化为 JSON
    jsonData, err := json.Marshal(cvssVector)
    if err != nil {
        log.Fatalf("JSON 序列化失败: %v", err)
    }
    
    fmt.Println("紧凑 JSON:")
    fmt.Println(string(jsonData))
    
    // 美化输出
    prettyJSON, err := json.MarshalIndent(cvssVector, "", "  ")
    if err != nil {
        log.Fatalf("JSON 美化失败: %v", err)
    }
    
    fmt.Println("\n美化 JSON:")
    fmt.Println(string(prettyJSON))
}
```

### JSON 反序列化

```go
func deserializeExample() {
    jsonStr := `{
        "MajorVersion": 3,
        "MinorVersion": 1,
        "Cvss3xBase": {
            "AttackVector": {
                "value": "N",
                "score": 0.85
            },
            "AttackComplexity": {
                "value": "L", 
                "score": 0.77
            }
        }
    }`
    
    var cvssVector cvss.Cvss3x
    err := json.Unmarshal([]byte(jsonStr), &cvssVector)
    if err != nil {
        log.Fatalf("JSON 反序列化失败: %v", err)
    }
    
    fmt.Printf("反序列化成功: %s\n", cvssVector.String())
}
```

## JSON 结构

### 基础结构

```json
{
  "MajorVersion": 3,
  "MinorVersion": 1,
  "Cvss3xBase": {
    "AttackVector": {
      "groupName": "Exploitability",
      "shortName": "AV",
      "longName": "Attack Vector",
      "shortValue": "N",
      "longValue": "Network",
      "description": "Network",
      "score": 0.85
    },
    "AttackComplexity": {
      "groupName": "Exploitability",
      "shortName": "AC",
      "longName": "Attack Complexity",
      "shortValue": "L",
      "longValue": "Low",
      "description": "Low",
      "score": 0.77
    }
  }
}
```

### 包含时间指标

```json
{
  "MajorVersion": 3,
  "MinorVersion": 1,
  "Cvss3xBase": { /* 基础指标 */ },
  "Cvss3xTemporal": {
    "ExploitCodeMaturity": {
      "shortValue": "F",
      "score": 0.97
    },
    "RemediationLevel": {
      "shortValue": "O",
      "score": 0.95
    },
    "ReportConfidence": {
      "shortValue": "C",
      "score": 1.0
    }
  }
}
```

### 包含环境指标

```json
{
  "MajorVersion": 3,
  "MinorVersion": 1,
  "Cvss3xBase": { /* 基础指标 */ },
  "Cvss3xEnvironmental": {
    "ConfidentialityRequirement": {
      "shortValue": "H",
      "score": 1.5
    },
    "ModifiedAttackVector": {
      "shortValue": "L",
      "score": 0.55
    }
  }
}
```

## 完整示例

### 数据持久化

```go
package main

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    
    "github.com/scagogogo/cvss-parser/pkg/parser"
    "github.com/scagogogo/cvss-parser/pkg/cvss"
)

// 保存 CVSS 向量到文件
func saveCVSSToFile(vectorStr, filename string) error {
    // 解析向量
    p := parser.NewCvss3xParser(vectorStr)
    cvssVector, err := p.Parse()
    if err != nil {
        return fmt.Errorf("解析失败: %w", err)
    }
    
    // 序列化为 JSON
    jsonData, err := json.MarshalIndent(cvssVector, "", "  ")
    if err != nil {
        return fmt.Errorf("JSON 序列化失败: %w", err)
    }
    
    // 写入文件
    err = ioutil.WriteFile(filename, jsonData, 0644)
    if err != nil {
        return fmt.Errorf("写入文件失败: %w", err)
    }
    
    return nil
}

// 从文件加载 CVSS 向量
func loadCVSSFromFile(filename string) (*cvss.Cvss3x, error) {
    // 读取文件
    jsonData, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, fmt.Errorf("读取文件失败: %w", err)
    }
    
    // 反序列化
    var cvssVector cvss.Cvss3x
    err = json.Unmarshal(jsonData, &cvssVector)
    if err != nil {
        return nil, fmt.Errorf("JSON 反序列化失败: %w", err)
    }
    
    return &cvssVector, nil
}

func main() {
    vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    filename := "cvss_vector.json"
    
    // 保存到文件
    err := saveCVSSToFile(vectorStr, filename)
    if err != nil {
        log.Fatalf("保存失败: %v", err)
    }
    fmt.Printf("CVSS 向量已保存到 %s\n", filename)
    
    // 从文件加载
    cvssVector, err := loadCVSSFromFile(filename)
    if err != nil {
        log.Fatalf("加载失败: %v", err)
    }
    
    fmt.Printf("从文件加载的向量: %s\n", cvssVector.String())
    
    // 计算评分
    calculator := cvss.NewCalculator(cvssVector)
    score, err := calculator.Calculate()
    if err != nil {
        log.Fatalf("计算失败: %v", err)
    }
    
    fmt.Printf("评分: %.1f\n", score)
}
```

### 批量处理

```go
type CVSSBatch struct {
    Vectors []cvss.Cvss3x `json:"vectors"`
    Metadata struct {
        CreatedAt string `json:"created_at"`
        Source    string `json:"source"`
        Count     int    `json:"count"`
    } `json:"metadata"`
}

func processBatch(vectorStrings []string) (*CVSSBatch, error) {
    batch := &CVSSBatch{}
    batch.Metadata.CreatedAt = time.Now().Format(time.RFC3339)
    batch.Metadata.Source = "CVSS Parser"
    
    for _, vectorStr := range vectorStrings {
        p := parser.NewCvss3xParser(vectorStr)
        cvssVector, err := p.Parse()
        if err != nil {
            continue // 跳过无效向量
        }
        
        batch.Vectors = append(batch.Vectors, *cvssVector)
    }
    
    batch.Metadata.Count = len(batch.Vectors)
    return batch, nil
}
```

### API 集成

```go
// HTTP API 示例
func cvssHandler(w http.ResponseWriter, r *http.Request) {
    vectorStr := r.URL.Query().Get("vector")
    if vectorStr == "" {
        http.Error(w, "缺少 vector 参数", http.StatusBadRequest)
        return
    }
    
    // 解析向量
    p := parser.NewCvss3xParser(vectorStr)
    cvssVector, err := p.Parse()
    if err != nil {
        http.Error(w, fmt.Sprintf("解析失败: %v", err), http.StatusBadRequest)
        return
    }
    
    // 计算评分
    calculator := cvss.NewCalculator(cvssVector)
    score, err := calculator.Calculate()
    if err != nil {
        http.Error(w, fmt.Sprintf("计算失败: %v", err), http.StatusInternalServerError)
        return
    }
    
    // 构建响应
    response := struct {
        Vector   *cvss.Cvss3x `json:"vector"`
        Score    float64      `json:"score"`
        Severity string       `json:"severity"`
    }{
        Vector:   cvssVector,
        Score:    score,
        Severity: calculator.GetSeverityRating(score),
    }
    
    // 返回 JSON 响应
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}
```

## 自定义序列化

### 自定义 JSON 标签

```go
type CustomCVSS struct {
    Version string  `json:"version"`
    Vector  string  `json:"vector"`
    Score   float64 `json:"score"`
    Level   string  `json:"severity_level"`
}

func (c *CustomCVSS) FromCVSS(cvss *cvss.Cvss3x) error {
    c.Version = fmt.Sprintf("%d.%d", cvss.MajorVersion, cvss.MinorVersion)
    c.Vector = cvss.String()
    
    calculator := cvss.NewCalculator(cvss)
    score, err := calculator.Calculate()
    if err != nil {
        return err
    }
    
    c.Score = score
    c.Level = calculator.GetSeverityRating(score)
    return nil
}
```

### 压缩格式

```go
type CompactCVSS struct {
    V string  `json:"v"` // 向量字符串
    S float64 `json:"s"` // 评分
    L string  `json:"l"` // 级别
}

func toCompact(cvss *cvss.Cvss3x) (*CompactCVSS, error) {
    calculator := cvss.NewCalculator(cvss)
    score, err := calculator.Calculate()
    if err != nil {
        return nil, err
    }
    
    return &CompactCVSS{
        V: cvss.String(),
        S: score,
        L: calculator.GetSeverityRating(score),
    }, nil
}
```

## 最佳实践

### 1. 错误处理

```go
func safeJSONMarshal(v interface{}) ([]byte, error) {
    data, err := json.Marshal(v)
    if err != nil {
        return nil, fmt.Errorf("JSON 序列化失败: %w", err)
    }
    return data, nil
}

func safeJSONUnmarshal(data []byte, v interface{}) error {
    err := json.Unmarshal(data, v)
    if err != nil {
        return fmt.Errorf("JSON 反序列化失败: %w", err)
    }
    return nil
}
```

### 2. 验证反序列化结果

```go
func validateDeserialized(cvss *cvss.Cvss3x) error {
    if err := cvss.Check(); err != nil {
        return fmt.Errorf("反序列化的 CVSS 向量无效: %w", err)
    }
    return nil
}
```

### 3. 版本兼容性

```go
type VersionedCVSS struct {
    SchemaVersion string      `json:"schema_version"`
    Data          cvss.Cvss3x `json:"data"`
}

func createVersionedCVSS(cvss *cvss.Cvss3x) *VersionedCVSS {
    return &VersionedCVSS{
        SchemaVersion: "1.0",
        Data:          *cvss,
    }
}
```

## 性能考虑

### 内存使用

```go
// 使用流式处理大量数据
func processLargeJSONFile(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()
    
    decoder := json.NewDecoder(file)
    
    for decoder.More() {
        var cvss cvss.Cvss3x
        if err := decoder.Decode(&cvss); err != nil {
            continue // 跳过无效记录
        }
        
        // 处理单个 CVSS 向量
        processVector(&cvss)
    }
    
    return nil
}
```

### 缓存序列化结果

```go
var jsonCache = make(map[string][]byte)
var cacheMutex sync.RWMutex

func getCachedJSON(vectorStr string) ([]byte, bool) {
    cacheMutex.RLock()
    defer cacheMutex.RUnlock()
    
    data, exists := jsonCache[vectorStr]
    return data, exists
}

func setCachedJSON(vectorStr string, data []byte) {
    cacheMutex.Lock()
    defer cacheMutex.Unlock()
    
    jsonCache[vectorStr] = data
}
```

## 相关文档

- [Cvss3x 数据结构](/api/cvss/cvss3x)
- [Parser 解析器](/api/parser/cvss3x-parser)
- [JSON 示例](/examples/json)
