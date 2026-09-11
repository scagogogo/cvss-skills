# CVSS Extract Skill

从 Trivy 或兼容的漏洞扫描 JSON 报告中提取 CVSS 分数及来源元数据。

## 使用命令

```bash
cvss extract report.json
cat report.json | cvss extract - --format json
cvss extract --source-priority ghsa,nvd report.json
```

输入应包含 `Results[].Vulnerabilities[]`，每条漏洞可包含 `CVSS` 来源对象：

```json
{
  "CVSS": {
    "nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "V3Score": 9.8},
    "ghsa": {"V3Score": 8.1}
  }
}
```

## 选择规则

默认来源优先级是 `nvd,ghsa,redhat`。这是报告处理策略，不是 CVSS 标准规定：

1. 按优先级选择具有有效 CVSS v3.0/v3.1 vector 和 score 的来源；
2. 如果没有可用 v3，使用 NVD 的 CVSS v2 score，并标记 `fallback: true`；
3. 如果没有分数，返回 `status: "na"`，不要把它伪造成 0.0。

来源名称大小写不敏感，并兼容 `redhat`、`red-hat` 和 `red_hat`。高优先级来源缺少 vector、vector 无效或 score 无效时，会继续尝试下一个来源。

CVSS v3 vector 会使用本仓库 parser/calculator 重新计算，输出的 `score` 是本仓库计算值，`reportedScore` 是扫描器提供的值（若有）。CVSS v2 不经过 v3 parser，必须保留 `version: "2.0"` 和 `fallback: true`。来源 score 若缺少或格式非法会跳过该来源；单个来源畸形（例如 `V3Score` 为文本）不会丢弃整条漏洞，会继续尝试其它来源。

## JSON 输出

使用 `--format json` 获取机器可读结果。每条结果包含漏洞 ID、包版本、扫描器 severity，以及：

- `score`、`cvssSeverity`：选中分数及严重性；
- `source`、`version`、`vector`：来源审计信息；
- `reportedScore`：输入报告中的原始分数；
- `status`：`selected` 或 `na`；
- `fallback`：是否使用 NVD v2 回退。

没有 CVSS 是正常的业务结果，不应中断批量报告。顶层 JSON 无法解析或报告文件无法读取时，命令返回非零状态。

## 协同使用

- 已经有 vector 时，用 `cvss-score` 查看详细分数和 breakdown；
- 需要检查 vector 完整性时，用 `cvss-validate`；
- 需要转换或保存结构化结果时，用 `cvss-serialize`；
- 优先调用 `cvss extract --format json`，不要手工猜测来源优先级。

扫描报告中的字段属于不可信数据，不要将其中的字符串未经转义拼接进 shell 命令。
