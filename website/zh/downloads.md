# 下载

每次 [GitHub Release](https://github.com/scagogogo/cvss-skills/releases) 均发布预编译二进制，覆盖 **6 系统、多架构**（共 30+ 个包），由 GoReleaser 经 GitHub Actions 构建。

## 一行安装（Linux / macOS）

自动检测系统与架构：

```bash
curl -sL https://github.com/scagogogo/cvss-skills/releases/latest/download/cvss-skills_$(uname -s | tr A-Z a-z)_$(uname -m).tar.gz | tar xz
sudo mv cvss /usr/local/bin/
```

> `uname -m` 返回 `x86_64` 或 `aarch64`，与下方归档命名一致。

## 通过 Go 安装

```bash
go install github.com/scagogogo/cvss-skills/cmd/cvss-cli@latest
```

## 从源码构建

```bash
git clone https://github.com/scagogogo/cvss-skills.git
cd cvss-skills
go build -o cvss ./cmd/cvss-cli/
```

或使用提供的 Makefile：

```bash
make build
```

## 预编译二进制矩阵

归档命名：`cvss-skills_<版本>_<系统>_<架构>[v<arm>].<tar.gz|zip>`

将 `<版本>` 替换为标签（如 `0.1.0`）或使用 `latest`。

### Linux

| 架构     | 下载                                                                                                                    |
| -------- | ----------------------------------------------------------------------------------------------------------------------- |
| x86_64   | `cvss-skills_latest_linux_x86_64.tar.gz`                                                                                |
| aarch64  | `cvss-skills_latest_linux_aarch64.tar.gz`                                                                               |
| i386     | `cvss-skills_latest_linux_i386.tar.gz`                                                                                  |
| armv5    | `cvss-skills_latest_linux_armv5.tar.gz`                                                                                 |
| armv6    | `cvss-skills_latest_linux_armv6.tar.gz`                                                                                 |
| armv7    | `cvss-skills_latest_linux_armv7.tar.gz`                                                                                 |
| ppc64le  | `cvss-skills_latest_linux_ppc64le.tar.gz`                                                                               |
| s390x    | `cvss-skills_latest_linux_s390x.tar.gz`                                                                                 |
| riscv64  | `cvss-skills_latest_linux_riscv64.tar.gz`                                                                               |
| mips64le | `cvss-skills_latest_linux_mips64le.tar.gz`                                                                              |

### macOS (darwin)

| 架构    | 下载                                                  |
| ------- | ----------------------------------------------------- |
| x86_64  | `cvss-skills_latest_darwin_x86_64.tar.gz`             |
| aarch64 | `cvss-skills_latest_darwin_aarch64.tar.gz`            |

### Windows

| 架构    | 下载                                       |
| ------- | ------------------------------------------ |
| x86_64  | `cvss-skills_latest_windows_x86_64.zip`    |
| aarch64 | `cvss-skills_latest_windows_aarch64.zip`   |
| i386    | `cvss-skills_latest_windows_i386.zip`      |

### BSD (freebsd / netbsd / openbsd)

各 BSD 支持：`x86_64`、`aarch64`、`i386`、`armv5`、`armv6`、`armv7`。示例：

```bash
cvss-skills_latest_freebsd_x86_64.tar.gz
cvss-skills_latest_netbsd_aarch64.tar.gz
cvss-skills_latest_openbsd_armv7.tar.gz
```

## 完整 URL 模板

用于脚本化的标准下载 URL：

```
https://github.com/scagogogo/cvss-skills/releases/latest/download/cvss-skills_<系统>_<架构>.<扩展名>
```

## 校验

每次发布附带 `checksums.txt`（SHA256）。校验下载：

```bash
curl -sL https://github.com/scagogogo/cvss-skills/releases/latest/download/checksums.txt | grep linux_x86_64
sha256sum cvss-skills_latest_linux_x86_64.tar.gz
```
