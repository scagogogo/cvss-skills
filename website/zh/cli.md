---
title: 命令行参考
description: cvss 命令行工具完整参考 —— 30+ 命令，用于解析、评分、校验、比较与分析 CVSS v3.0/v3.1 向量，全部支持 JSON 输出。
---

# 命令行参考

`cvss` CLI 提供 **30+ 命令**，用于解析、评分、校验、比较与分析 CVSS 向量。每条命令均支持 `--format json` 以输出结构化数据。

## 安装

::: code-group

```bash [curl（预编译二进制）]
os=$(uname -s | tr '[:upper:]' '[:lower:]'); arch=$(uname -m)
case "$arch" in arm64) arch=aarch64 ;; amd64) arch=x86_64 ;; esac
curl -sL "https://github.com/scagogogo/cvss-skills/releases/latest/download/cvss-skills_${os}_${arch}.tar.gz" | tar xz
sudo mv cvss /usr/local/bin/
```

```bash [go install]
go install github.com/scagogogo/cvss-skills/cmd/cvss-cli@latest
```

:::

预编译二进制覆盖 **6 系统 × 8 架构** —— 见[下载](/zh/downloads/)。

## 命令地图

30+ 命令可归为六大功能组：

```mermaid
mindmap
  root((cvss CLI))
    评分与评级
      score
      severity
      describe
      analyze
    解析与构建
      parse
      build
      validate
      canonicalize
    比较
      diff
      merge
      distance
      equal
    变换
      modify
      strip
      convert
      map
    检视指标
      get
      enumerate
      groups
      subs
    批量与 IO
      json
      csv
      batch
      sort
      range
      preset
      random
```

## 命令

| 命令                | 描述                 | 示例                                                                     |
| ------------------- | -------------------- | ------------------------------------------------------------------------ |
| `cvss score`        | 计算 CVSS 评分       | `cvss score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`             |
| `cvss parse`        | 解析向量字符串       | `cvss parse "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`             |
| `cvss validate`     | 校验向量字符串       | `cvss validate "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`          |
| `cvss build`        | 从指标标志构建       | `cvss build --av N --ac L --pr N --ui N --s U --c H --i H --a H`        |
| `cvss describe`     | 人类可读描述         | `cvss describe "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`          |
| `cvss diff`         | 比较两个向量         | `cvss diff "CVSS:3.1/..." "CVSS:3.1/..."`                              |
| `cvss merge`        | 合并两个向量         | `cvss merge "CVSS:3.1/..." "CVSS:3.1/..."`                             |
| `cvss distance`     | 计算距离度量         | `cvss distance "CVSS:3.1/..." "CVSS:3.1/..."`                          |
| `cvss analyze`      | 影响/敏感性分析      | `cvss analyze "CVSS:3.1/..."`                                          |
| `cvss range`        | 部分向量的分数范围   | `cvss range "CVSS:3.1/AV:N"`                                           |
| `cvss preset`       | 生成预设向量         | `cvss preset critical-network`                                         |
| `cvss random`       | 生成随机向量         | `cvss random --version 3.1`                                            |
| `cvss json`         | JSON 序列化          | `cvss json "CVSS:3.1/..."`                                             |
| `cvss csv`          | CSV 文件读写         | `cvss csv input.csv --output results.csv`                              |
| `cvss batch`        | 批量操作             | `cvss batch --file vectors.txt`                                        |
| `cvss severity`     | 获取严重性等级       | `cvss severity "CVSS:3.1/..."`                                         |
| `cvss sort`         | 按分数排序向量       | `cvss sort file.csv`                                                   |
| `cvss canonicalize` | 规范化向量格式       | `cvss canonicalize "CVSS:3.1/..."`                                     |
| `cvss convert`      | 版本间转换           | `cvss convert "CVSS:3.0/..." --to 3.1`                                 |
| `cvss enumerate`    | 枚举指标取值         | `cvss enumerate AV`                                                    |
| `cvss equal`        | 比较两个向量         | `cvss equal "CVSS:3.1/..." "CVSS:3.1/..."`                             |
| `cvss get`          | 获取指定指标值       | `cvss get AV "CVSS:3.1/..."`                                           |
| `cvss groups`       | 显示指标分组         | `cvss groups`                                                          |
| `cvss map`          | 映射/变换向量        | `cvss map --preset high-severity`                                      |
| `cvss modify`       | 修改指标值           | `cvss modify AV L "CVSS:3.1/..."`                                      |
| `cvss strip`        | 剥离时间/环境指标    | `cvss strip "CVSS:3.1/..."`                                            |
| `cvss subs`         | 显示指标替换         | `cvss subs`                                                            |

运行 `cvss --help` 查看完整列表，`cvss <命令> --help` 查看单命令选项。

## JSON 输出

每条命令接受 `--format json` 以输出机器可读结果 —— 适合通过管道传入 `jq` 等工具：

```bash
cvss score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" --format json | jq .score
```

### 用管道组合命令

由于每条命令都是「读入向量、输出 JSON」，命令可以干净地串联，用于批量定级：

```mermaid
flowchart LR
    F[("vectors.txt")] --> B["cvss batch"]
    B -->|"--format json"| S["cvss sort<br/>按评分降序"]
    S --> J["jq '.[] | select(.score >= 9.0)'"]
    J --> Out(["仅保留严重漏洞"])

    classDef io fill:#f9f0ff,stroke:#722ed1,color:#391085;
    class F,Out io;
```
