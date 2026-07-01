# Downloads

Pre-built binaries are published with every [GitHub Release](https://github.com/scagogogo/cvss-skills/releases). They cover **6 operating systems across many architectures** (30+ packages total), built by GoReleaser via GitHub Actions.

## One-Line Install (Linux / macOS)

Auto-detects your OS and architecture:

```bash
curl -sL https://github.com/scagogogo/cvss-skills/releases/latest/download/cvss-skills_$(uname -s | tr A-Z a-z)_$(uname -m).tar.gz | tar xz
sudo mv cvss /usr/local/bin/
```

> `uname -m` returns `x86_64` or `aarch64`, which matches the archive naming convention below.

## Install via Go

```bash
go install github.com/scagogogo/cvss-skills/cmd/cvss-cli@latest
```

## Build from Source

```bash
git clone https://github.com/scagogogo/cvss-skills.git
cd cvss-skills
go build -o cvss ./cmd/cvss-cli/
```

Or use the provided Makefile:

```bash
make build
```

## Pre-built Binary Matrix

Archive naming: `cvss-skills_<version>_<os>_<arch>[v<arm>].<tar.gz|zip>`

Replace `<version>` with a tag (e.g. `0.1.0`) or use `latest`.

### Linux

| Arch      | Download                                                                                                                |
| --------- | ----------------------------------------------------------------------------------------------------------------------- |
| x86_64    | `cvss-skills_latest_linux_x86_64.tar.gz`                                                                                |
| aarch64   | `cvss-skills_latest_linux_aarch64.tar.gz`                                                                               |
| i386      | `cvss-skills_latest_linux_i386.tar.gz`                                                                                  |
| armv5     | `cvss-skills_latest_linux_armv5.tar.gz`                                                                                 |
| armv6     | `cvss-skills_latest_linux_armv6.tar.gz`                                                                                 |
| armv7     | `cvss-skills_latest_linux_armv7.tar.gz`                                                                                 |
| ppc64le   | `cvss-skills_latest_linux_ppc64le.tar.gz`                                                                               |
| s390x     | `cvss-skills_latest_linux_s390x.tar.gz`                                                                                 |
| riscv64   | `cvss-skills_latest_linux_riscv64.tar.gz`                                                                               |
| mips64le  | `cvss-skills_latest_linux_mips64le.tar.gz`                                                                              |

### macOS (darwin)

| Arch    | Download                                                  |
| ------- | --------------------------------------------------------- |
| x86_64  | `cvss-skills_latest_darwin_x86_64.tar.gz`                 |
| aarch64 | `cvss-skills_latest_darwin_aarch64.tar.gz`                |

### Windows

| Arch    | Download                                       |
| ------- | ---------------------------------------------- |
| x86_64  | `cvss-skills_latest_windows_x86_64.zip`        |
| aarch64 | `cvss-skills_latest_windows_aarch64.zip`       |
| i386    | `cvss-skills_latest_windows_i386.zip`          |

### BSD (freebsd / netbsd / openbsd)

Each BSD supports: `x86_64`, `aarch64`, `i386`, `armv5`, `armv6`, `armv7`. Example:

```bash
cvss-skills_latest_freebsd_x86_64.tar.gz
cvss-skills_latest_netbsd_aarch64.tar.gz
cvss-skills_latest_openbsd_armv7.tar.gz
```

## Full URL Template

For scripting, the canonical download URL is:

```
https://github.com/scagogogo/cvss-skills/releases/latest/download/cvss-skills_<os>_<arch>.<ext>
```

## Verification

Every release ships a `checksums.txt` (SHA256). Verify a download:

```bash
curl -sL https://github.com/scagogogo/cvss-skills/releases/latest/download/checksums.txt | grep linux_x86_64
sha256sum cvss-skills_latest_linux_x86_64.tar.gz
```
