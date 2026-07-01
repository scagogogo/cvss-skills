---
layout: home

hero:
  name: CVSS Skills
  text: CVSS v3.0 / v3.1 Toolkit
  tagline: Parse, score, validate, compare & build vulnerability vectors — through Go SDK, CLI, Claude Code Skills & MCP.
  image:
    src: /images/integration-methods.png
    alt: Four integration methods of CVSS Skills
  actions:
    - theme: brand
      text: Get Started
      link: /integration/
    - theme: alt
      text: Download CLI
      link: /downloads/
    - theme: alt
      text: GitHub
      link: https://github.com/scagogogo/cvss-skills

features:
  - icon: 🤖
    title: 4 Integration Methods
    details: Claude Code Skills, Go SDK, CLI, and MCP — pick the one that fits your workflow, from natural language to batch scripting.
    link: /integration/
    linkText: Compare methods →
  - icon: 🧮
    title: Spec-Accurate Scoring
    details: Base / Temporal / Environmental scores following CVSS v3.0 & v3.1 specs, including version-specific quirks (e.g. UI:R = 0.56 vs 0.62).
  - icon: ✅
    title: Structured Validation
    details: Per-metric error reporting, completeness checks, and missing-metric detection — no more guessing what's wrong with a vector.
  - icon: 📊
    title: Compare & Measure
    details: Diff, merge, and distance metrics (Euclidean, Manhattan, Hamming, Jaccard) with environment-aware variants.
  - icon: 💻
    title: 30+ CLI Commands
    details: Scriptable CLI with JSON output for every command. Pre-built binaries for 6 OS × 8 architectures.
    link: /cli/
    linkText: Browse commands →
  - icon: 📦
    title: One-Line Install
    details: Go SDK via go get, CLI via curl or go install, Skills via a single claude mcp add command.
---

## What Problem Does This Solve?

CVSS is the industry standard for rating vulnerability severity, but working with vectors programmatically is painful — parsing is error-prone, scoring involves version-specific formulas, comparison is manual, and validation is scattered.

**CVSS Skills** solves all of this with a single, well-tested toolkit.

![Feature Map](/images/feature-map.png)

## CVSS Vector Structure

A CVSS vector consists of up to **3 layers** of metrics:

![Vector Structure](/images/vector-structure.png)

## Severity Scale

![Severity Gauge](/images/severity-gauge.png)

| Rating   | Score Range | Color   |
| -------- | ----------- | ------- |
| None     | 0.0         | Gray    |
| Low      | 0.1 – 3.9   | Green   |
| Medium   | 4.0 – 6.9   | Yellow  |
| High     | 7.0 – 8.9   | Orange  |
| Critical | 9.0 – 10.0  | Red     |

## Quick Start

::: code-group

```bash [Claude Code Skills]
claude mcp add --scope user cvss-skills -- https://github.com/scagogogo/cvss-skills
```

```bash [Go SDK]
go get github.com/scagogogo/cvss-skills@latest
```

```bash [CLI (curl)]
curl -sL https://github.com/scagogogo/cvss-skills/releases/latest/download/cvss-skills_$(uname -s | tr A-Z a-z)_$(uname -m).tar.gz | tar xz
sudo mv cvss /usr/local/bin/
```

```bash [CLI (go install)]
go install github.com/scagogogo/cvss-skills/cmd/cvss-cli@latest
```

:::

```bash
# Score a vector — works the same in every integration
cvss score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
# Output: 9.8 (Critical)
```
