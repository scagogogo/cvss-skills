<div align="center">

# CVSS Skills

**Professional CVSS v3.0 / v3.1 Toolkit — Parse, Score, Validate, Compare & Build Vulnerability Vectors**

[![Go Tests and Examples](https://github.com/scagogogo/cvss/actions/workflows/go-test.yml/badge.svg)](https://github.com/scagogogo/cvss/actions/workflows/go-test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/scagogogo/cvss)](https://goreportcard.com/report/github.com/scagogogo/cvss)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Languages**: English | [简体中文](README_zh.md)

</div>

---

## What Problem Does This Solve?

CVSS (Common Vulnerability Scoring System) is the industry standard for rating vulnerability severity, but working with CVSS vectors programmatically is painful:

- **Parsing is error-prone** — vector strings like `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` need careful handling of versions, metrics, and values
- **Scoring is complex** — base, temporal, and environmental scores involve different formulas with version-specific quirks (e.g., `UI:R` = 0.56 in v3.0 vs 0.62 in v3.1)
- **Comparison is manual** — diffing, merging, and measuring distance between vectors requires understanding all metric interactions
- **Validation is scattered** — checking completeness, finding missing metrics, and reporting per-metric errors is tedious
- **No unified tooling** — security teams juggle spreadsheets, web calculators, and custom scripts

**CVSS Skills** solves all of this with a single, well-tested toolkit available through **4 integration methods**:

| | Integration | Best For |
|---|---|---|
| 🤖 | **Skills** (Claude Code) | Interactive analysis, natural language queries |
| 📦 | **Go SDK** | Building security tools and automation in Go |
| 💻 | **CLI** | Scripting, batch processing, quick lookups |
| 🔌 | **MCP** | AI agent integration via Model Context Protocol |

![Integration Methods](docs/images/integration-methods.png)

---

## Feature Map

![Feature Map](docs/images/feature-map.png)

### Key Capabilities

| Category | Features |
|----------|----------|
| **Parsing** | Parse v3.0/v3.1 vectors, relaxed parsing (no `CVSS:` prefix), `ParseAndScore` one-liner, Builder API, `FromMap` |
| **Scoring** | Base / Temporal / Environmental scores, severity ratings, per-metric score breakdown |
| **Validation** | Structural validation, `ValidationErrors` with per-metric reporting, `IsComplete()`, `MissingMetrics()` |
| **Comparison** | Diff (per-metric comparison), Merge, Equal / SameSeverity checks |
| **Distance** | Euclidean, Manhattan, Hamming, Jaccard similarity — with environment-aware variants |
| **Serialization** | JSON marshal/unmarshal, text marshal/unmarshal, CSV I/O, batch processing |
| **Advanced** | Sensitivity analysis, score range for partial vectors, version-aware scoring, presets, mock data generators |

---

## Quick Start

### 1. Skills (Claude Code) — One Command

```bash
claude mcp add --scope user cvss-skills -- https://github.com/scagogogo/cvss-skills
```

This enables **9 CVSS skills** inside Claude Code:

| Skill | Description |
|-------|-------------|
| `/cvss-parse` | Parse CVSS v3.0/v3.1 vector strings |
| `/cvss-score` | Calculate base/temporal/environmental scores |
| `/cvss-validate` | Validate vector completeness and correctness |
| `/cvss-construct` | Build vectors with the Builder API |
| `/cvss-compare` | Diff, merge, and distance calculations |
| `/cvss-metrics` | Enumerate and inspect metric definitions |
| `/cvss-serialize` | JSON/text serialization and deserialization |
| `/cvss-advanced` | Sensitivity analysis, score ranges, presets |
| `/cvss-install` | Install CLI tool and Go SDK dependency |

<details>
<summary>Manual installation</summary>

Add to your project's `.claude/settings.json` or `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "cvss-skills": {
      "type": "github",
      "url": "https://github.com/scagogogo/cvss-skills"
    }
  }
}
```

</details>

### 2. Go SDK — Full-Featured Library

```bash
go get github.com/scagogogo/cvss-skills@latest
```

```go
package main

import (
    "fmt"
    "log"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    // One-step parse and score
    cv, score, severity, err := parser.ParseAndScore(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Score: %.1f (%s)\n", score, severity) // Score: 9.8 (Critical)
    _ = cv
}
```

### 3. CLI — 30+ Commands

```bash
# Install from GitHub Release
curl -sL https://github.com/scagogogo/cvss-skills/releases/latest/download/cvss-skills_$(uname -s | tr A-Z a-z)_$(uname -m).tar.gz | tar xz
mv cvss /usr/local/bin/

# Or install with Go
go install github.com/scagogogo/cvss-skills/cmd/cvss-cli@latest

# Use
cvss score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
# Output: 9.8 (Critical)
```

### 4. MCP — AI Agent Integration

Connect this repository as an MCP server from any MCP-compatible client to use CVSS tools through the standard Model Context Protocol.

---

## CVSS Vector Structure

![Vector Structure](docs/images/vector-structure.png)

A CVSS vector consists of up to **3 layers** of metrics:

| Layer | Metrics | Required |
|-------|---------|----------|
| **Base** | AV, AC, PR, UI, S, C, I, A | Yes (all 8) |
| **Temporal** | E, RL, RC | No |
| **Environmental** | CR, IR, AR, MAV, MAC, MPR, MUI, MS, MC, MI, MA | No |

---

## Severity Scale

![Severity Gauge](docs/images/severity-gauge.png)

| Rating | Score Range | Color |
|--------|------------|-------|
| None | 0.0 | Gray |
| Low | 0.1 – 3.9 | Green |
| Medium | 4.0 – 6.9 | Yellow |
| High | 7.0 – 8.9 | Orange |
| Critical | 9.0 – 10.0 | Red |

---

## Go SDK Examples

### Parse and Calculate

```go
cvssVector, err := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
if err != nil {
    log.Fatalf("Parse failed: %v", err)
}

calculator := cvss.NewCalculator(cvssVector)
score, _ := calculator.Calculate()
fmt.Printf("CVSS Score: %.1f\n", score)              // 9.8
fmt.Printf("Severity: %s\n", cvss.GetSeverity(score)) // Critical
```

### Builder API

```go
cv := cvss.NewBuilder().Version(3, 1).
    AV('N').AC('L').PR('N').UI('N').S('U').
    C('H').I('H').A('H').MustBuild()

score, _ := cvss.NewCalculator(cv).Calculate()
fmt.Printf("Score: %.1f\n", score) // 9.8
```

### Structured Validation

```go
err := cv.Validate()
if ve, ok := err.(cvss.ValidationErrors); ok {
    fmt.Printf("Missing: %v\n", ve.MissingMetrics())
}
```

### Diff and Merge

```go
diffs := cv1.Diff(cv2)
for _, d := range diffs {
    fmt.Printf("%s: %s vs %s\n", d.Metric, d.V1, d.V2)
}

merged := cv1.Merge(cv2WithTemporal)
```

### Distance Calculation

```go
dc := cvss.NewDistanceCalculator(cv1, cv2)
fmt.Printf("Euclidean: %.2f\n", dc.EuclideanDistance())
fmt.Printf("Manhattan: %.2f\n", dc.ManhattanDistance())
fmt.Printf("Jaccard: %.2f\n", dc.JaccardSimilarity())
```

### Score Breakdown

```go
calc := cvss.NewCalculator(cv)
breakdown, _ := calc.GetScoreBreakdown()
for _, m := range breakdown.AllMetrics() {
    fmt.Printf("%s:%s = %.2f\n", m.ShortName, m.Value, m.Score)
}
```

### Convenience Methods

```go
cv.IsComplete()         // true if all 8 base metrics set
cv.Is31()               // true if CVSS v3.1
cv.HasTemporalMetrics() // true if temporal metrics present
cv.HasEnvironmentalMetrics() // true if environmental metrics present
cv.MissingMetrics()     // list of missing metric names
cv.Clone()              // deep copy
cv.BaseOnly()           // clone without temporal/environmental
cv.Equal(other)         // exact metric comparison
cv.EqualScore(other)    // score-based comparison
cv.SameSeverity(other)  // severity-based comparison
```

---

## CLI Commands

| Command | Description | Example |
|---------|-------------|---------|
| `cvss score` | Calculate CVSS scores | `cvss score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"` |
| `cvss parse` | Parse a vector string | `cvss parse "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"` |
| `cvss validate` | Validate a vector string | `cvss validate "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"` |
| `cvss build` | Build from metric flags | `cvss build --av N --ac L --pr N --ui N --s U --c H --i H --a H` |
| `cvss describe` | Human-readable description | `cvss describe "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"` |
| `cvss diff` | Compare two vectors | `cvss diff "CVSS:3.1/..." "CVSS:3.1/..."` |
| `cvss merge` | Merge two vectors | `cvss merge "CVSS:3.1/..." "CVSS:3.1/..."` |
| `cvss distance` | Calculate distance metrics | `cvss distance "CVSS:3.1/..." "CVSS:3.1/..."` |
| `cvss analyze` | Impact/sensitivity analysis | `cvss analyze "CVSS:3.1/..."` |
| `cvss range` | Score range for partial vectors | `cvss range "CVSS:3.1/AV:N"` |
| `cvss preset` | Generate preset vectors | `cvss preset critical-network` |
| `cvss random` | Generate random vectors | `cvss random --version 3.1` |
| `cvss json` | JSON serialization | `cvss json "CVSS:3.1/..."` |
| `cvss csv` | CSV file I/O | `cvss csv input.csv --output results.csv` |
| `cvss batch` | Batch operations | `cvss batch --file vectors.txt` |
| `cvss severity` | Get severity rating | `cvss severity "CVSS:3.1/..."` |
| `cvss sort` | Sort vectors by score | `cvss sort file.csv` |
| `cvss canonicalize` | Canonicalize vector format | `cvss canonicalize "CVSS:3.1/..."` |
| `cvss convert` | Convert between versions | `cvss convert "CVSS:3.0/..." --to 3.1` |
| `cvss enumerate` | Enumerate metric values | `cvss enumerate AV` |
| `cvss equal` | Compare two vectors | `cvss equal "CVSS:3.1/..." "CVSS:3.1/..."` |
| `cvss get` | Get specific metric value | `cvss get AV "CVSS:3.1/..."` |
| `cvss groups` | Show metric groups | `cvss groups` |
| `cvss map` | Map/transform vectors | `cvss map --preset high-severity` |
| `cvss modify` | Modify a metric value | `cvss modify AV L "CVSS:3.1/..."` |
| `cvss strip` | Strip temporal/env metrics | `cvss strip "CVSS:3.1/..."` |
| `cvss subs` | Show metric substitutions | `cvss subs` |

All commands support `--format json` for structured output. Run `cvss --help` for the full list.

---

## Documentation

**[Complete Documentation Website](https://scagogogo.github.io/cvss/)**

- [API Reference](https://scagogogo.github.io/cvss/api/) — Complete API documentation
- [Examples & Tutorials](https://scagogogo.github.io/cvss/examples/) — Practical usage examples
- [Quick Start Guide](https://scagogogo.github.io/cvss/api/getting-started) — Get started in 5 minutes
- [Chinese Documentation](https://scagogogo.github.io/cvss/zh/) — Full Chinese docs

---

## Contributing

We welcome contributions, issue reports, and suggestions!

- [GitHub Issues](https://github.com/scagogogo/cvss/issues) — Report issues or suggestions
- [Contributing Guide](https://scagogogo.github.io/cvss/contributing) — How to contribute code
- [Development Docs](https://scagogogo.github.io/cvss/development) — Development environment setup

## License

MIT License — see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [CVSS v3.0 Specification](https://www.first.org/cvss/v3.0/specification-document)
