# CVSS Parser

[![Go Tests and Examples](https://github.com/scagogogo/cvss/actions/workflows/go-test.yml/badge.svg)](https://github.com/scagogogo/cvss/actions/workflows/go-test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/scagogogo/cvss)](https://goreportcard.com/report/github.com/scagogogo/cvss)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Languages**: [English](README.md) | [简体中文](README_zh.md)

CVSS Parser is a Go library for parsing, calculating, and processing CVSS (Common Vulnerability Scoring System) vectors. It supports CVSS 3.0 and 3.1 versions, providing comprehensive functionality for vulnerability management and security assessment.

## 📖 Documentation

**🌐 [Complete Documentation Website](https://scagogogo.github.io/cvss/)**

Visit our comprehensive documentation website for:
- 📚 **[API Reference](https://scagogogo.github.io/cvss/api/)** - Complete API documentation
- 💡 **[Examples & Tutorials](https://scagogogo.github.io/cvss/examples/)** - Practical usage examples
- 🚀 **[Quick Start Guide](https://scagogogo.github.io/cvss/api/getting-started)** - Get started in 5 minutes
- 🌍 **[中文文档](https://scagogogo.github.io/cvss/zh/)** - Chinese documentation

## Features

- Support for CVSS 3.0 and 3.1 vector parsing and calculation
- Calculate base, temporal, and environmental scores
- **Builder API** for fluent vector construction
- **Structured validation** with per-metric error reporting
- **Diff/Merge** for comparing and combining vectors
- **Score breakdown** with per-metric effective scores
- JSON serialization/deserialization (MarshalJSON/UnmarshalJSON)
- Vector comparison: Euclidean, Manhattan, Hamming, Jaccard distances
- **Environment-aware distance** calculations
- Version-aware scoring (v3.0 UI:R=0.56 vs v3.1 UI:R=0.62)
- Severity convenience methods (IsCritical, IsHigh, etc.)
- ParseRelaxed for vectors without CVSS prefix
- Mock data generators for testing
- High test coverage (500+ tests)

## Installation

```bash
go get github.com/scagogogo/cvss
```

## Quick Start

### Parse and Calculate

```go
package main

import (
    "fmt"
    "log"

    "github.com/scagogogo/cvss-parser/pkg/cvss"
    "github.com/scagogogo/cvss-parser/pkg/parser"
)

func main() {
    // Parse CVSS vector
    cvssVector, err := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    if err != nil {
        log.Fatalf("Parse failed: %v", err)
    }

    // Calculate score
    calculator := cvss.NewCalculator(cvssVector)
    score, err := calculator.Calculate()
    if err != nil {
        log.Fatalf("Calculation failed: %v", err)
    }

    fmt.Printf("CVSS Score: %.1f\n", score)
    fmt.Printf("Severity: %s\n", calculator.GetSeverityRating(score))
}
```

### Builder API

```go
cv := cvss.NewBuilder().Version(3, 1).
    AV('N').AC('L').PR('N').UI('N').S('U').
    C('H').I('H').A('H').MustBuild()

score, _ := cvss.NewCalculator(cv).Calculate()
fmt.Printf("Score: %.1f\n", score) // 9.8
```

### ParseRelaxed (without prefix)

```go
// Parse vectors without the "CVSS:3.1/" prefix
cv, err := parser.ParseRelaxed("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "3.1")
```

### Structured Validation

```go
cv := cvss.NewCvss3x()
cv.MajorVersion = 3
cv.MinorVersion = 1
cv.Cvss3xBase.AttackVector = vector.AttackVectorNetwork

err := cv.Validate()
if ve, ok := err.(cvss.ValidationErrors); ok {
    missing := ve.MissingMetrics()
    fmt.Printf("Missing: %v\n", missing) // [AC, PR, UI, S, C, I, A]
}
```

### Diff and Merge

```go
cv1 := cvss.NewBuilder().Version(3, 1).AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').MustBuild()
cv2 := cvss.NewBuilder().Version(3, 1).AV('L').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').MustBuild()

diffs := cv1.Diff(cv2)
for _, d := range diffs {
    fmt.Printf("%s: %s vs %s\n", d.Metric, d.V1, d.V2) // AV: N vs L
}

merged := cv1.Merge(cv2WithTemporal) // Overlay temporal onto base
```

### Score Breakdown

```go
calculator := cvss.NewCalculator(cv)
breakdown, _ := calculator.GetScoreBreakdown()
fmt.Printf("AV score: %.2f\n", breakdown.AttackVector.Score)    // 0.85
fmt.Printf("PR score: %.2f\n", breakdown.PrivilegesRequired.Score) // 0.62 (scope-adjusted)
```

### Distance Calculation

```go
dc := cvss.NewDistanceCalculator(cv1, cv2)
fmt.Printf("Euclidean: %.2f\n", dc.EuclideanDistance())
fmt.Printf("Jaccard: %.2f\n", dc.JaccardSimilarity())
fmt.Printf("JaccardWithEnv: %.2f\n", dc.JaccardSimilarityWithEnv())
```

### Convenience Methods

```go
cv.IsComplete()                    // true if all 8 base metrics are set
cv.Is30()                          // true if CVSS v3.0
cv.Is31()                          // true if CVSS v3.1
cv.HasTemporalMetrics()            // true if any temporal metric is set
cv.Description()                   // "Attack Vector: Network, ..."
cv.Clone()                         // deep copy
cv.BaseOnly()                      // clone without temporal/environmental
cv.MissingMetrics()                // list of missing metric short names

cvss.SeverityCritical.IsCritical() // true
cvss.GetSeverity(9.8)              // SeverityCritical
```

### Mock Data

```go
import "github.com/scagogogo/cvss-parser/pkg/mock"

cv := mock.CriticalCvss31()           // preset Critical vector
cv := mock.RandomCvss3x(1)            // random CVSS 3.1
cv := mock.RandomCvss3xFull(1)        // random with all metrics
```

### JSON Serialization

```go
// Cvss3x implements json.Marshaler/Unmarshaler
data, _ := json.Marshal(cv)           // "CVSS:3.1/AV:N/..."
var restored cvss.Cvss3x
json.Unmarshal(data, &restored)       // restores full Cvss3x
```

## 📚 Learning Resources

### Quick Start
- [5-Minute Quick Start](https://scagogogo.github.io/cvss/api/getting-started) - Fastest way to get started
- [Basic Examples](https://scagogogo.github.io/cvss/examples/basic) - Simple usage examples

### Deep Dive
- [CVSS Package Guide](https://scagogogo.github.io/cvss/api/cvss/) - Core functionality introduction
- [Parser Usage](https://scagogogo.github.io/cvss/api/parser/) - String parsing
- [Vector Analysis](https://scagogogo.github.io/cvss/api/cvss/distance) - Advanced analysis features

### Practical Examples
- [JSON Processing](https://scagogogo.github.io/cvss/examples/json) - Data serialization
- [Batch Processing](https://scagogogo.github.io/cvss/examples/parsing) - Batch vector parsing
- [Similarity Analysis](https://scagogogo.github.io/cvss/examples/distance) - Vector comparison

## Contributing

We welcome code contributions, issue reports, and improvement suggestions! Please check our:

- [GitHub Issues](https://github.com/scagogogo/cvss/issues) - Report issues or suggestions
- [Contributing Guide](https://scagogogo.github.io/cvss/contributing) - Learn how to contribute code
- [Development Documentation](https://scagogogo.github.io/cvss/development) - Development environment setup

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [CVSS v3.0 Specification](https://www.first.org/cvss/v3.0/specification-document)