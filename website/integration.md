# Integration Methods

CVSS Skills is available through **four** integration methods. Pick the one that fits your workflow.

![Integration Methods](/images/integration-methods.png)

|          | Integration                | Best For                                    | Install                                                                     |
| -------- | -------------------------- | ------------------------------------------- | --------------------------------------------------------------------------- |
| 🤖       | **Skills** (Claude Code)   | Interactive analysis, natural language      | `claude mcp add --scope user cvss-skills -- https://github.com/scagogogo/cvss-skills` |
| 📦       | **Go SDK**                 | Building security tools & automation in Go | `go get github.com/scagogogo/cvss-skills@latest`                            |
| 💻       | **CLI**                    | Scripting, batch processing, quick lookups  | See [Downloads](/downloads/)                                               |
| 🔌       | **MCP**                    | AI agent integration via Model Context      | Add this repo as an MCP server from any MCP-compatible client               |

## 1. Claude Code Skills

One command enables **9 CVSS skills** inside Claude Code:

| Skill               | Description                                  |
| ------------------- | -------------------------------------------- |
| `/cvss-parse`       | Parse CVSS v3.0/v3.1 vector strings          |
| `/cvss-score`       | Calculate base/temporal/environmental scores |
| `/cvss-validate`    | Validate vector completeness and correctness |
| `/cvss-construct`   | Build vectors with the Builder API           |
| `/cvss-compare`     | Diff, merge, and distance calculations       |
| `/cvss-metrics`     | Enumerate and inspect metric definitions     |
| `/cvss-serialize`   | JSON/text serialization and deserialization  |
| `/cvss-advanced`    | Sensitivity analysis, score ranges, presets |
| `/cvss-install`     | Install CLI tool and Go SDK dependency       |

::: details Manual installation
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

:::

## 2. Go SDK

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

Full API reference: [API Docs](/docs/api/).

## 3. CLI

```bash
cvss score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
# Output: 9.8 (Critical)
```

See the [CLI Reference](/cli/) for all 30+ commands.

## 4. MCP

Connect this repository as an MCP server from any MCP-compatible client (Claude Desktop, Continue, custom agents) to use CVSS tools through the standard Model Context Protocol.
