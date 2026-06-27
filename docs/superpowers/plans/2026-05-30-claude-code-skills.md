# Claude Code Skills Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 为 CVSS Parser Go 库项目添加 Claude Code Skills 支持，通过 `.claude/commands/` 自定义命令让开发者可以直接在 Claude Code 中使用 `/cvss-parse`、`/cvss-score` 等斜杠命令快速操作 CVSS 向量。

**Architecture:** 用户在 Claude Code 中输入 `/cvss-parse CVSS:3.1/AV:N/...` → Skills 命令将 `$ARGUMENTS` 传递给 Claude → Claude 根据命令模板生成 Go 代码或执行操作 → 开发者得到可直接运行的代码片段。创建项目级 `.claude/commands/` 目录存放 7 个 Skill 命令文件，创建 `CLAUDE.md` 项目级指引文件。复用项目现有的 Go 包结构（`pkg/parser`、`pkg/cvss`、`pkg/vector`），Skills 作为开发者体验层不修改任何库代码。

**Tech Stack:** Claude Code Custom Commands (Markdown), Go 1.18, CVSS v3.0/v3.1 specification

**Risks:**
- 项目当前没有 `.claude/` 目录，需要从零创建 → 缓解：创建目录结构是低风险操作
- Skills 中的代码示例需要与库的实际 API 完全一致 → 缓解：基于现有 examples/ 目录的代码编写，已验证可编译
- `.claude/` 目录可能被 gitignore → 缓解：检查 .gitignore 并确保 `.claude/commands/` 被提交

---

### Task 1: 创建项目基础设施 — `.claude/` 目录和 `CLAUDE.md`

**Depends on:** None
**Files:**
- Create: `.claude/commands/` (directory)
- Create: `CLAUDE.md`
- Modify: `.gitignore` (如需要)

- [ ] **Step 1: 创建 `.claude/commands/` 目录 — 存放项目级自定义 Skill 命令**

```bash
mkdir -p .claude/commands
```

- [ ] **Step 2: 创建 `CLAUDE.md` — 项目级 Claude Code 指引文件**

```markdown
# CLAUDE.md — CVSS Parser Project Guidelines

## Project Overview

This is `github.com/scagogogo/cvss-skills`, a Go library for parsing, calculating, and processing CVSS (Common Vulnerability Scoring System) v3.0 and v3.1 vector strings.

## Architecture

- `pkg/vector/` — Value objects for each CVSS metric (AV, AC, PR, UI, S, C, I, A, etc.)
- `pkg/parser/` — CVSS vector string parser (`Cvss3xParser`, `VectorParser`)
- `pkg/cvss/` — Core data model (`Cvss3x`), score calculator (`Calculator`), JSON output, distance/similarity
- `examples/` — Runnable Go example programs
- `docs/` — VitePress documentation site

## Common Commands

- `make test` — Run unit tests
- `make test-ci` — Run CI tests (with race detector, coverage, build all examples)
- `make build` — Build CLI binary to `bin/cvss-cli`
- `make coverage` — Generate HTML coverage report

## Code Style

- Go 1.18 minimum, follow standard Go conventions
- Use `stretchr/testify` for assertions in tests
- Vector types implement the `Vector` interface with singleton instances
- Parser is hand-written recursive-descent (no parser generator)
- All CVSS metric scores follow the FIRST specification formulas

## Key Patterns

- Parse a vector: `parser.NewCvss3xParser(vectorString).Parse()` returns `*cvss.Cvss3x`
- Calculate score: `cvss.NewCalculator(cvss3x).Calculate()` returns `float64`
- Get severity: `cvss.NewCalculator(cvss3x).GetSeverityRating(score)` returns `string`
- JSON output: `cvss3x.ToJSON(calculator)` returns structured map
- Compare vectors: `cvss.NewDistanceCalculator(a, b).EuclideanDistance()`

## CVSS Vector Format

Standard format: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

- Base metrics: AV, AC, PR, UI, S, C, I, A (all required)
- Temporal metrics: E, RL, RC (optional)
- Environmental metrics: CR, IR, AR, MAV, MAC, MPR, MUI, MS, MC, MI, MA (optional)
```

- [ ] **Step 3: 检查并更新 `.gitignore` — 确保 `.claude/commands/` 不会被忽略**

```bash
# Check if .claude is in gitignore
if grep -q '\.claude' .gitignore 2>/dev/null; then
  echo "Found .claude in gitignore, need to add exception"
  # We'll handle this in the modify step
else
  echo "No .claude entry in gitignore, commands will be tracked"
fi
```

- [ ] **Step 4: 验证目录结构**
Run: `ls -la .claude/commands/ && test -f CLAUDE.md && echo "CLAUDE.md exists"`
Expected:
  - Exit code: 0
  - Output contains: "commands"
  - Output contains: "CLAUDE.md exists"

- [ ] **Step 5: 提交**
Run: `git add .claude/commands/ CLAUDE.md && git commit -m "feat(claude-code): add .claude/commands directory and CLAUDE.md project guide"`

---

### Task 2: 创建核心 CVSS 操作 Skills — parse、score、compare

**Depends on:** Task 1
**Files:**
- Create: `.claude/commands/cvss-parse.md`
- Create: `.claude/commands/cvss-score.md`
- Create: `.claude/commands/cvss-compare.md`

- [ ] **Step 1: 创建 `/cvss-parse` Skill — 解析 CVSS 向量字符串并输出详细信息**

```markdown
---
description: Parse a CVSS vector string and show all metrics, scores, and severity
argument-hint: <CVSS:3.x/AV:.../AC:.../...>
allowed-tools: [Bash, Read, Write]
---

Parse the following CVSS vector string and generate a complete Go program that shows all metrics, scores, and severity rating.

CVSS Vector: $ARGUMENTS

Generate a Go program that:

1. Imports `github.com/scagogogo/cvss-skills/pkg/parser` and `github.com/scagogogo/cvss-skills/pkg/cvss`
2. Parses the vector string using `parser.NewCvss3xParser(vectorString).Parse()`
3. Prints each metric's short name, short value, long name, long value, and numeric score
4. Calculates the base/temporal/environmental score using `cvss.NewCalculator(cvss3x).Calculate()`
5. Prints the severity rating using `cvss.NewCalculator(cvss3x).GetSeverityRating(score)`
6. Outputs JSON representation using `cvss3x.ToJSON(nil)`

Use this code structure:

```go
package main

import (
	"fmt"
	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
	vectorString := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

	// Parse
	result, err := parser.NewCvss3xParser(vectorString).Parse()
	if err != nil {
		panic(err)
	}

	// Print metrics
	fmt.Println("=== CVSS Vector Parsed ===")
	fmt.Printf("Vector: %s\n", result.String())

	// Calculate score
	calc := cvss.NewCalculator(result)
	score := calc.Calculate()
	severity := calc.GetSeverityRating(score)

	fmt.Printf("Score: %.1f\n", score)
	fmt.Printf("Severity: %s\n", severity)

	// JSON output
	jsonOutput := result.ToJSON(nil)
	fmt.Printf("JSON: %v\n", jsonOutput)
}
```

Replace the vector string with the one provided by the user. After generating the code, offer to run it with `go run`.
```

- [ ] **Step 2: 创建 `/cvss-score` Skill — 计算 CVSS 分数和严重等级**

```markdown
---
description: Calculate CVSS score and severity rating from a vector string
argument-hint: <CVSS:3.x/AV:.../AC:.../...>
allowed-tools: [Bash, Read, Write]
---

Calculate the CVSS score and severity rating for the following vector string.

CVSS Vector: $ARGUMENTS

Generate a Go program that:

1. Parses the vector string
2. Calculates all available scores (base, temporal, environmental)
3. Shows the severity rating
4. Displays a formatted score breakdown

Use this code structure:

```go
package main

import (
	"fmt"
	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
	vectorString := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

	result, err := parser.NewCvss3xParser(vectorString).Parse()
	if err != nil {
		panic(err)
	}

	calc := cvss.NewCalculator(result)

	// Base score
	fmt.Printf("Base Score: %.1f\n", calc.CalculateBaseScore())
	fmt.Printf("Base Severity: %s\n", calc.GetSeverityRating(calc.CalculateBaseScore()))

	// Temporal score (if temporal metrics present)
	temporalScore := calc.CalculateTemporalScore()
	if temporalScore >= 0 {
		fmt.Printf("Temporal Score: %.1f\n", temporalScore)
		fmt.Printf("Temporal Severity: %s\n", calc.GetSeverityRating(temporalScore))
	}

	// Environmental score (if environmental metrics present)
	envScore := calc.CalculateEnvironmentalScore()
	if envScore >= 0 {
		fmt.Printf("Environmental Score: %.1f\n", envScore)
		fmt.Printf("Environmental Severity: %s\n", calc.GetSeverityRating(envScore))
	}

	// Overall
	overallScore := calc.Calculate()
	fmt.Printf("\nOverall Score: %.1f (%s)\n", overallScore, calc.GetSeverityRating(overallScore))
}
```

Replace the vector string with the user's input. After generating, offer to run it.
```

- [ ] **Step 3: 创建 `/cvss-compare` Skill — 比较两个 CVSS 向量的差异和相似度**

```markdown
---
description: Compare two CVSS vectors using distance algorithms (Euclidean, Manhattan, Hamming, Jaccard)
argument-hint: <vector1> | <vector2>
allowed-tools: [Bash, Read, Write]
---

Compare two CVSS vectors and calculate their similarity and difference metrics.

Vectors to compare: $ARGUMENTS

The two vectors should be separated by " | " (pipe with spaces).

Generate a Go program that:

1. Parses both CVSS vector strings
2. Creates a distance calculator using `cvss.NewDistanceCalculator(vec1, vec2)`
3. Calculates and prints all distance/similarity metrics:
   - Euclidean Distance
   - Manhattan Distance
   - Hamming Distance
   - Jaccard Similarity
   - Score Difference
4. Highlights which metrics differ between the two vectors

Use this code structure:

```go
package main

import (
	"fmt"
	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
	vector1Str := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	vector2Str := "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N"

	vec1, err := parser.NewCvss3xParser(vector1Str).Parse()
	if err != nil {
		panic(err)
	}
	vec2, err := parser.NewCvss3xParser(vector2Str).Parse()
	if err != nil {
		panic(err)
	}

	dc := cvss.NewDistanceCalculator(vec1, vec2)

	fmt.Println("=== CVSS Vector Comparison ===")
	fmt.Printf("Vector 1: %s\n", vector1Str)
	fmt.Printf("Vector 2: %s\n", vector2Str)
	fmt.Println()
	fmt.Printf("Euclidean Distance: %.4f\n", dc.EuclideanDistance())
	fmt.Printf("Manhattan Distance:  %.4f\n", dc.ManhattanDistance())
	fmt.Printf("Hamming Distance:    %d\n", dc.HammingDistance())
	fmt.Printf("Jaccard Similarity:  %.4f\n", dc.JaccardSimilarity())
	fmt.Printf("Score Difference:    %.1f\n", dc.ScoreDifference())
}
```

Replace both vector strings with the user's input. After generating, offer to run it.
```

- [ ] **Step 4: 验证 Skills 文件存在且格式正确**
Run: `for f in .claude/commands/cvss-parse.md .claude/commands/cvss-score.md .claude/commands/cvss-compare.md; do echo "=== $f ==="; head -3 "$f"; echo; done`
Expected:
  - Exit code: 0
  - Output contains: "description:" in each file
  - Output contains: "argument-hint:" in each file

- [ ] **Step 5: 提交**
Run: `git add .claude/commands/cvss-parse.md .claude/commands/cvss-score.md .claude/commands/cvss-compare.md && git commit -m "feat(claude-code): add cvss-parse, cvss-score, cvss-compare skills"`

---

### Task 3: 创建辅助 Skills — explain、spec、example

**Depends on:** Task 1
**Files:**
- Create: `.claude/commands/cvss-explain.md`
- Create: `.claude/commands/cvss-spec.md`
- Create: `.claude/commands/cvss-example.md`

- [ ] **Step 1: 创建 `/cvss-explain` Skill — 解释 CVSS 向量中每个指标的含义**

```markdown
---
description: Explain each metric in a CVSS vector string with detailed descriptions
argument-hint: <CVSS:3.x/AV:.../AC:.../...>
allowed-tools: [Bash, Read]
---

Explain every metric in the following CVSS vector string in detail.

CVSS Vector: $ARGUMENTS

For each metric in the vector, provide:

1. **Short Name** (e.g., AV, AC, PR)
2. **Full Name** (e.g., Attack Vector, Attack Complexity, Privileges Required)
3. **Selected Value** (e.g., N, L, H)
4. **Value Meaning** (e.g., Network, Low, High)
5. **What This Means** — A clear explanation of why this value was chosen and its impact on the overall score
6. **Numeric Weight** — The score weight this value contributes

After explaining each metric, provide a summary:

- **Base Score**: The calculated base score and severity
- **Impact**: What kind of impact this vulnerability could have
- **Exploitability**: How easy it is to exploit
- **Overall Assessment**: A plain-language summary of the vulnerability severity

Reference the CVSS v3.1 specification at `docs/cvss-specification-document.html` for authoritative definitions.

Use the library to parse and calculate:

```go
package main

import (
	"fmt"
	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
	vectorString := "$ARGUMENTS"
	result, err := parser.NewCvss3xParser(vectorString).Parse()
	if err != nil {
		panic(err)
	}
	calc := cvss.NewCalculator(result)
	score := calc.Calculate()
	severity := calc.GetSeverityRating(score)
	fmt.Printf("Score: %.1f (%s)\n", score, severity)
	fmt.Println(result.ToJSON(nil))
}
```
```

- [ ] **Step 2: 创建 `/cvss-spec` Skill — 查询 CVSS 规范中特定指标的定义**

```markdown
---
description: Look up CVSS specification details for a specific metric or value
argument-hint: <metric-name-or-value, e.g. AV or PR:L or Attack Vector>
allowed-tools: [Bash, Read]
---

Look up the CVSS specification details for: $ARGUMENTS

Search the project's CVSS specification document at `docs/cvss-specification-document.html` and the Go source code in `pkg/vector/` to provide:

1. **Metric Definition**: The official FIRST specification definition
2. **Possible Values**: All valid values for this metric with their meanings
3. **Score Weights**: The numeric weight each value contributes to the score
4. **Scope Considerations**: How this metric interacts with Scope (Changed vs Unchanged)
5. **Code Reference**: The Go struct and constants that implement this metric in the library

If the user asks about a specific metric value (e.g., "PR:L"), also explain:

- What "L" means in context (Low)
- When to select this value
- How it affects the overall score calculation

Search strategy:
1. Read `docs/cvss-specification-document.html` for the official definition
2. Read the corresponding file in `pkg/vector/` (e.g., `pkg/vector/privileges_required.go` for PR)
3. Read `pkg/cvss/calculator.go` to show how this metric's score is used in calculations
```

- [ ] **Step 3: 创建 `/cvss-example` Skill — 生成特定场景的 CVSS 代码示例**

```markdown
---
description: Generate a Go code example for a specific CVSS use case
argument-hint: <use-case: parsing|scoring|json|temporal|environmental|comparison|distance|severity>
allowed-tools: [Bash, Read, Write]
---

Generate a complete, runnable Go code example for the following CVSS use case: $ARGUMENTS

Available use cases:
- **parsing** — Parse CVSS vector strings
- **scoring** — Calculate CVSS scores
- **json** — Generate JSON output
- **temporal** — Work with temporal metrics
- **environmental** — Work with environmental metrics
- **comparison** — Compare two CVSS vectors
- **distance** — Calculate distance/similarity between vectors
- **severity** — Get severity ratings

First, check the existing examples in the `examples/` directory for reference patterns. Read the relevant example file(s) before generating code.

Generate a complete Go program that:

1. Has a `package main` and `func main()`
2. Imports the correct packages from `github.com/scagogogo/cvss-skills/pkg/...`
3. Includes helpful comments explaining each step
4. Uses realistic CVSS vector strings
5. Handles errors properly
6. Prints clear, formatted output

After generating the code, offer to:
1. Save it to a new file in the `examples/` directory
2. Run it with `go run`
```

- [ ] **Step 4: 验证 Skills 文件存在且格式正确**
Run: `for f in .claude/commands/cvss-explain.md .claude/commands/cvss-spec.md .claude/commands/cvss-example.md; do echo "=== $f ==="; head -3 "$f"; echo; done`
Expected:
  - Exit code: 0
  - Output contains: "description:" in each file

- [ ] **Step 5: 提交**
Run: `git add .claude/commands/cvss-explain.md .claude/commands/cvss-spec.md .claude/commands/cvss-example.md && git commit -m "feat(claude-code): add cvss-explain, cvss-spec, cvss-example skills"`

---

### Task 4: 创建开发者工具 Skill — cvss-test

**Depends on:** Task 1
**Files:**
- Create: `.claude/commands/cvss-test.md`

- [ ] **Step 1: 创建 `/cvss-test` Skill — 为 CVSS 功能生成和运行测试**

```markdown
---
description: Generate and run tests for CVSS parsing, scoring, or comparison functionality
argument-hint: <target: parser|calculator|distance|vector|all>
allowed-tools: [Bash, Read, Write]
---

Generate and run tests for the CVSS library targeting: $ARGUMENTS

Available targets:
- **parser** — Test CVSS vector string parsing
- **calculator** — Test score calculation and severity ratings
- **distance** — Test vector comparison and distance algorithms
- **vector** — Test individual vector metric definitions
- **all** — Run all existing tests

First, read the existing test files to understand the current test patterns:

- `pkg/cvss/calculator_test.go` — Calculator tests
- `pkg/cvss/distance_test.go` — Distance tests
- `pkg/parser/cvss3x_parser_test.go` — Parser tests
- `pkg/vector/factory_test.go` — Vector factory tests

Then:

1. If target is "all": run `make test` and report results
2. If target is a specific package: generate additional test cases covering:
   - Happy path: Valid input, expected correct output
   - Edge cases: Boundary values, minimum/maximum scores
   - Error cases: Invalid vectors, missing metrics, malformed strings

Generated tests should follow the existing patterns in the project:
- Use `stretchr/testify/assert` for assertions
- Use table-driven tests where appropriate
- Include CVSS spec reference comments

After generating tests, run them with `go test ./pkg/<target>/... -v` and report results.
```

- [ ] **Step 2: 验证 Skill 文件存在且格式正确**
Run: `head -5 .claude/commands/cvss-test.md`
Expected:
  - Exit code: 0
  - Output contains: "description:"

- [ ] **Step 3: 提交**
Run: `git add .claude/commands/cvss-test.md && git commit -m "feat(claude-code): add cvss-test skill for generating and running tests"`

---

### Task 5: 更新项目文档和 `.gitignore`

**Depends on:** Task 2, Task 3, Task 4
**Files:**
- Modify: `README.md` (添加 Skills 文档段落)
- Modify: `README_zh.md` (添加中文 Skills 文档段落)
- Modify: `.gitignore` (确保 `.claude/` 不被忽略，或仅忽略非必要文件)

- [ ] **Step 1: 检查 `.gitignore` 内容 — 确定 `.claude/` 的处理方式**

Run: `cat .gitignore`

根据结果决定是否需要修改。如果 `.gitignore` 中有忽略 `.claude/` 的规则，需要添加例外以保留 `.claude/commands/`。

- [ ] **Step 2: 更新 `README.md` — 添加 Claude Code Skills 文档段落**
文件: `README.md`（在文件末尾，License 段落之前添加）

在 README.md 中找到合适位置（Development 或 Contributing 段落附近），添加：

```markdown
## Claude Code Skills

This project includes custom Claude Code slash commands for CVSS operations. If you use [Claude Code](https://claude.ai/code), you can use these commands:

| Command | Description |
|---------|-------------|
| `/cvss-parse <vector>` | Parse a CVSS vector string and show all metrics |
| `/cvss-score <vector>` | Calculate CVSS score and severity rating |
| `/cvss-compare <v1> \| <v2>` | Compare two CVSS vectors using distance algorithms |
| `/cvss-explain <vector>` | Explain each metric in a CVSS vector |
| `/cvss-spec <metric>` | Look up CVSS specification details |
| `/cvss-example <use-case>` | Generate a Go code example |
| `/cvss-test <target>` | Generate and run tests |

Example usage:
```
/cvss-parse CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
/cvss-score CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
/cvss-compare CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N
```
```

- [ ] **Step 3: 更新 `README_zh.md` — 添加中文 Claude Code Skills 文档段落**
文件: `README_zh.md`（与 README.md 对应位置添加）

```markdown
## Claude Code Skills

本项目包含用于 CVSS 操作的 Claude Code 自定义斜杠命令。如果你使用 [Claude Code](https://claude.ai/code)，可以使用以下命令：

| 命令 | 描述 |
|------|------|
| `/cvss-parse <向量>` | 解析 CVSS 向量字符串并显示所有指标 |
| `/cvss-score <向量>` | 计算 CVSS 分数和严重等级 |
| `/cvss-compare <v1> \| <v2>` | 使用距离算法比较两个 CVSS 向量 |
| `/cvss-explain <向量>` | 解释 CVSS 向量中每个指标的含义 |
| `/cvss-spec <指标>` | 查询 CVSS 规范详细信息 |
| `/cvss-example <场景>` | 生成 Go 代码示例 |
| `/cvss-test <目标>` | 生成并运行测试 |

使用示例：
```
/cvss-parse CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
/cvss-score CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
/cvss-compare CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N
```
```

- [ ] **Step 4: 验证所有文件就绪**
Run: `ls -la .claude/commands/ && echo "---" && grep -c "cvss-" README.md && echo "---" && grep -c "cvss-" README_zh.md`
Expected:
  - Exit code: 0
  - `.claude/commands/` contains 7 .md files
  - README.md grep count >= 7
  - README_zh.md grep count >= 7

- [ ] **Step 5: 提交**
Run: `git add README.md README_zh.md .gitignore && git commit -m "docs: add Claude Code Skills documentation to README files"`
