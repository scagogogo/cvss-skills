---
layout: home

hero:
  name: CVSS Skills
  text: CVSS v3.0 / v3.1 工具包
  tagline: 解析、评分、验证、比较与构建漏洞向量 —— 通过 Go SDK、CLI、Claude Code Skills 与 MCP。
  image:
    src: /images/integration-methods.png
    alt: CVSS Skills 的四种集成方式
  actions:
    - theme: brand
      text: 快速开始
      link: /zh/integration/
    - theme: alt
      text: 下载 CLI
      link: /zh/downloads/
    - theme: alt
      text: GitHub
      link: https://github.com/scagogogo/cvss-skills

features:
  - icon: 🤖
    title: 4 种集成方式
    details: Claude Code Skills、Go SDK、CLI 与 MCP —— 从自然语言到批量脚本，按需选择。
    link: /zh/integration/
    linkText: 对比各方式 →
  - icon: 🧮
    title: 符合规范的评分
    details: 基础 / 时间 / 环境评分严格遵循 CVSS v3.0 与 v3.1 规范，包含版本差异（如 UI:R = 0.56 vs 0.62）。
  - icon: ✅
    title: 结构化校验
    details: 逐指标错误报告、完整性检查与缺失指标检测 —— 不再猜测向量哪里出错。
  - icon: 📊
    title: 比较与度量
    details: Diff、合并与距离度量（欧氏、曼哈顿、汉明、Jaccard），含环境感知变体。
  - icon: 💻
    title: 30+ CLI 命令
    details: 可脚本化的 CLI，每条命令均支持 JSON 输出。预编译二进制覆盖 6 系统 × 8 架构。
    link: /zh/cli/
    linkText: 浏览命令 →
  - icon: 📦
    title: 一行安装
    details: Go SDK 用 go get，CLI 用 curl 或 go install，Skills 用一条 claude mcp add 命令。
---

## 解决什么问题？

CVSS 是业界标准的漏洞严重性评级体系，但以编程方式处理向量十分痛苦 —— 解析易错、评分涉及版本特定公式、比较依赖手工、校验零散。

**CVSS Skills** 用一个经过充分测试的工具包解决上述所有问题。

![功能全景图](/images/feature-map.png)

## CVSS 向量结构

一个 CVSS 向量最多由 **3 层**指标构成：

![向量结构](/images/vector-structure.png)

## 严重性等级

![严重性仪表盘](/images/severity-gauge.png)

| 等级     | 分数范围    | 颜色   |
| -------- | ----------- | ------ |
| None     | 0.0         | 灰色   |
| Low      | 0.1 – 3.9   | 绿色   |
| Medium   | 4.0 – 6.9   | 黄色   |
| High     | 7.0 – 8.9   | 橙色   |
| Critical | 9.0 – 10.0  | 红色   |

## 快速开始

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
# 对向量评分 —— 每种集成方式效果相同
cvss score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
# 输出: 9.8 (Critical)
```
