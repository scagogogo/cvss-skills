# CVSS Parser

[![Go Tests and Examples](https://github.com/scagogogo/cvss/actions/workflows/go-test.yml/badge.svg)](https://github.com/scagogogo/cvss/actions/workflows/go-test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/scagogogo/cvss)](https://goreportcard.com/report/github.com/scagogogo/cvss)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Languages**: [English](README.md) | [简体中文](README_zh.md)

CVSS Parser is a Go library for parsing, calculating, and processing CVSS (Common Vulnerability Scoring System) vectors. It supports CVSS 3.0 and 3.1 versions, providing comprehensive functionality for vulnerability management and security assessment.

## Features

- Support for CVSS 3.0 and 3.1 vector parsing and calculation
- Calculate base, temporal, and environmental scores
- JSON output and formatting capabilities
- Vector comparison and similarity calculation
- Strict and tolerant parsing modes
- Complete documentation and examples
- High test coverage

## Installation

```bash
go get github.com/scagogogo/cvss
```

## Quick Start

Parse and calculate CVSS scores:

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

For more examples, see the [examples](./examples) directory.

## 📖 Documentation

- **[Online Documentation](https://scagogogo.github.io/cvss/)** - Complete API documentation and usage guide
- **[API Reference](https://scagogogo.github.io/cvss/api/)** - Detailed API documentation
- **[Examples Collection](https://scagogogo.github.io/cvss/examples/)** - Rich usage examples
- **[pkg.go.dev](https://pkg.go.dev/github.com/scagogogo/cvss)** - Official Go documentation

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





