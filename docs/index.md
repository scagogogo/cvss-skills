---
layout: home

hero:
  name: "CVSS Skills"
  text: "Go CVSS Parsing & Scoring Library"
  tagline: "Powerful, flexible, and easy-to-use CVSS 3.0/3.1 parsing, scoring, and analysis library"
  actions:
    - theme: brand
      text: Get Started
      link: /api/getting-started
    - theme: alt
      text: View Examples
      link: /examples/
    - theme: alt
      text: GitHub
      link: https://github.com/scagogogo/cvss-skills

features:
  - icon: 🚀
    title: High-Performance Parsing
    details: Fast and accurate parsing of CVSS 3.0 and 3.1 vector strings, supporting all standard and extended metrics.
  - icon: 🧮
    title: Complete Score Calculation
    details: Full support for base, temporal, and environmental score calculations, strictly following CVSS specifications.
  - icon: 📊
    title: Vector Analysis
    details: Advanced features including vector comparison, distance calculation, and similarity analysis for complex security assessments.
  - icon: 🔧
    title: Flexible Configuration
    details: Support for both strict and tolerant parsing modes, allowing you to choose the appropriate strategy for different scenarios.
  - icon: 📄
    title: JSON Support
    details: Complete JSON serialization and deserialization support for easy integration with other systems and data storage.
  - icon: 🧪
    title: High-Quality Code
    details: Comprehensive test coverage, detailed documentation and examples, ensuring code quality and maintainability.
---

## Quick Installation

```bash
go get github.com/scagogogo/cvss-skills
```

## Simple Example

```go
package main

import (
    "fmt"
    "log"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    // Parse CVSS vector
    p := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    cvssVector, err := p.Parse()
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

## Key Features

### 🎯 Complete CVSS Support

- **CVSS 3.0 and 3.1**: Full support for both CVSS specifications
- **All Metric Types**: Base metrics, temporal metrics, environmental metrics
- **Strict Validation**: Ensures vector format and value correctness

### 📈 Advanced Analysis Features

- **Vector Comparison**: Calculate similarity between CVSS vectors
- **Distance Calculation**: Multiple distance algorithm support
- **Batch Processing**: Efficiently process large amounts of vector data

### 🔌 Easy Integration

- **JSON Support**: Complete serialization and deserialization
- **Error Handling**: Detailed error messages and recovery mechanisms
- **Well Documented**: Rich examples and API documentation

## Use Cases

### 🛡️ Security Assessment

```go
// Assess vulnerability severity
vectors := []string{
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
}

for _, vectorStr := range vectors {
    // Parse and evaluate...
}
```

### 📊 Risk Analysis

```go
// Calculate vector distance
distCalc := cvss.NewDistanceCalculator(vector1, vector2)
distance := distCalc.EuclideanDistance()
fmt.Printf("Vector distance: %.3f\n", distance)
```

### 💾 Data Storage

```go
// JSON serialization
jsonData, err := json.Marshal(cvssVector)
if err != nil {
    log.Fatal(err)
}
```

## Get Started

1. **[Quick Start](/api/getting-started)** - 5-minute getting started guide
2. **[API Documentation](/api/)** - Complete API reference
3. **[Example Code](/examples/)** - Rich usage examples

## Community and Support

- 📖 [Complete Documentation](https://scagogogo.github.io/cvss-skills/)
- 🐛 [Issue Tracker](https://github.com/scagogogo/cvss-skills/issues)
- 💬 [Discussions](https://github.com/scagogogo/cvss-skills/discussions)
- 📧 [Contact Us](mailto:your-email@example.com)

---

<div style="text-align: center; margin-top: 2rem;">
  <p>
    <strong>CVSS Skills</strong> - Making CVSS processing simple and efficient
  </p>
  <p>
    <a href="/api/getting-started">Get Started</a> |
    <a href="https://github.com/scagogogo/cvss-skills">View Source</a> |
    <a href="/examples/">Browse Examples</a>
  </p>
</div>
