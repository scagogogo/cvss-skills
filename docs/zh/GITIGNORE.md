# .gitignore 文档

本文档解释了 CVSS Parser 项目中 `.gitignore` 文件的配置和最佳实践。

## 概述

`.gitignore` 文件告诉 Git 哪些文件和目录应该被忽略，不被版本控制跟踪。正确配置 `.gitignore` 对于保持仓库清洁和避免提交不必要的文件至关重要。

## 当前 .gitignore 配置

### Go 相关忽略

```gitignore
# Go 编译输出
*.exe
*.exe~
*.dll
*.so
*.dylib

# Go 测试二进制文件
*.test

# Go 覆盖率文件
*.out
coverage.txt
coverage.html

# Go 工作区文件
go.work
go.work.sum

# 依赖目录
vendor/

# Go 模块代理缓存
GOPROXY
GOSUMDB
```

**说明:**
- `*.exe`, `*.dll`, `*.so`, `*.dylib` - 编译后的二进制文件
- `*.test` - Go 测试生成的二进制文件
- `*.out`, `coverage.*` - 测试覆盖率报告文件
- `vendor/` - 依赖包目录（使用 Go modules 时通常不需要）

### 开发工具忽略

```gitignore
# IDE 和编辑器文件
.vscode/
.idea/
*.swp
*.swo
*~

# Vim 临时文件
.*.swp
.*.swo

# Emacs 临时文件
*~
\#*\#
/.emacs.desktop
/.emacs.desktop.lock
*.elc

# Sublime Text
*.sublime-project
*.sublime-workspace

# Atom
.atom/
```

**说明:**
- `.vscode/`, `.idea/` - IDE 配置目录
- `*.swp`, `*.swo` - Vim 临时文件
- `*~` - 编辑器备份文件

### 操作系统文件

```gitignore
# macOS
.DS_Store
.AppleDouble
.LSOverride
Icon?
._*

# Windows
Thumbs.db
ehthumbs.db
Desktop.ini
$RECYCLE.BIN/

# Linux
*~
.fuse_hidden*
.directory
.Trash-*
```

**说明:**
- `.DS_Store` - macOS 目录元数据文件
- `Thumbs.db` - Windows 缩略图缓存
- `.Trash-*` - Linux 回收站文件

### 构建和部署

```gitignore
# 构建输出
/build/
/dist/
/bin/
/pkg/

# 部署文件
*.tar.gz
*.zip
*.deb
*.rpm

# Docker
.dockerignore
Dockerfile.local
docker-compose.override.yml
```

**说明:**
- `/build/`, `/dist/`, `/bin/` - 构建输出目录
- `*.tar.gz`, `*.zip` - 打包文件
- Docker 相关的本地配置文件

### 文档和网站

```gitignore
# VitePress 构建输出
docs/.vitepress/dist/
docs/.vitepress/cache/

# Node.js (用于文档构建)
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# 文档临时文件
*.tmp
*.temp
```

**说明:**
- `docs/.vitepress/dist/` - VitePress 构建的静态文件
- `node_modules/` - Node.js 依赖包

### 测试和调试

```gitignore
# 测试输出
/test-results/
/coverage/
*.prof

# 调试文件
debug
debug.test
__debug_bin

# 基准测试结果
*.bench
benchmark.txt
```

**说明:**
- `/test-results/` - 测试结果目录
- `*.prof` - Go 性能分析文件
- `__debug_bin` - Delve 调试器生成的文件

### 配置和密钥

```gitignore
# 环境配置
.env
.env.local
.env.*.local

# 配置文件
config.local.yaml
config.local.json
*.local.conf

# 密钥和证书
*.key
*.pem
*.crt
*.p12
secrets/
```

**说明:**
- `.env*` - 环境变量文件
- `*.local.*` - 本地配置文件
- `*.key`, `*.pem` - 私钥和证书文件

### 日志和临时文件

```gitignore
# 日志文件
*.log
logs/
/var/log/

# 临时文件
tmp/
temp/
.tmp/
*.tmp
*.temp

# 缓存
.cache/
cache/
```

## 最佳实践

### 1. 分类组织

将 `.gitignore` 条目按类别组织，并添加注释：

```gitignore
# =============================================================================
# Go 语言相关
# =============================================================================

# 编译输出
*.exe
*.dll

# =============================================================================
# 开发工具
# =============================================================================

# IDE 配置
.vscode/
.idea/
```

### 2. 使用通配符

合理使用通配符模式：

```gitignore
# 匹配所有 .log 文件
*.log

# 匹配任何目录下的 node_modules
**/node_modules/

# 匹配根目录下的 build 目录
/build/

# 匹配任何位置的 .cache 目录
**/.cache/
```

### 3. 否定模式

使用 `!` 来包含被忽略目录中的特定文件：

```gitignore
# 忽略所有 .env 文件
.env*

# 但包含 .env.example
!.env.example

# 忽略 config 目录
config/

# 但包含示例配置
!config/config.example.yaml
```

### 4. 项目特定忽略

根据项目需求添加特定忽略：

```gitignore
# CVSS Parser 特定
/examples/output/
/benchmarks/results/
/tools/generated/

# 测试数据
/testdata/large/
/testdata/generated/
```

## 常见问题

### Q: 如何忽略已经被跟踪的文件？

A: 首先从 Git 中移除文件，然后添加到 `.gitignore`：

```bash
# 停止跟踪文件但保留在工作目录
git rm --cached filename

# 停止跟踪目录
git rm -r --cached directory/

# 提交更改
git commit -m "Remove tracked files now in .gitignore"
```

### Q: 如何检查 .gitignore 是否生效？

A: 使用以下命令检查：

```bash
# 检查文件是否被忽略
git check-ignore filename

# 查看所有被忽略的文件
git status --ignored

# 强制添加被忽略的文件
git add -f filename
```

### Q: 全局 .gitignore 与项目 .gitignore 的区别？

A: 
- **全局 .gitignore**: 适用于所有仓库，通常包含操作系统和编辑器文件
- **项目 .gitignore**: 特定于项目，包含项目相关的忽略规则

设置全局 .gitignore：
```bash
git config --global core.excludesfile ~/.gitignore_global
```

### Q: 如何为不同环境创建不同的忽略规则？

A: 可以使用条件包含：

```gitignore
# 开发环境
*.dev.log
.dev/

# 生产环境（通过环境变量控制）
# 在 CI/CD 中设置不同的 .gitignore
```

## 维护 .gitignore

### 定期审查

定期审查和更新 `.gitignore` 文件：

1. **添加新的忽略模式** - 当引入新工具或依赖时
2. **移除过时的模式** - 当不再使用某些工具时
3. **优化模式** - 使用更精确的模式避免意外忽略

### 团队协作

确保团队成员了解 `.gitignore` 规则：

1. **文档化** - 在项目文档中说明忽略规则
2. **代码审查** - 在 PR 中审查 `.gitignore` 变更
3. **一致性** - 确保所有开发者使用相同的忽略规则

### 模板使用

可以使用 GitHub 的 `.gitignore` 模板：

```bash
# 获取 Go 语言模板
curl https://raw.githubusercontent.com/github/gitignore/main/Go.gitignore > .gitignore
```

## 相关工具

### gitignore.io

使用 [gitignore.io](https://gitignore.io) 生成 `.gitignore` 文件：

```bash
# 为 Go、VSCode、macOS 生成 .gitignore
curl "https://www.toptal.com/developers/gitignore/api/go,vscode,macos" > .gitignore
```

### Git 命令

有用的 Git 命令：

```bash
# 查看被忽略的文件
git ls-files --others --ignored --exclude-standard

# 清理未跟踪的文件（包括被忽略的）
git clean -fdX

# 查看 .gitignore 规则的匹配情况
git check-ignore -v filename
```

## 总结

正确配置 `.gitignore` 文件对于维护干净的 Git 仓库至关重要。它应该：

1. **包含所有不应版本控制的文件类型**
2. **按类别组织并添加注释**
3. **定期更新以反映项目变化**
4. **在团队中保持一致**

通过遵循这些最佳实践，您可以确保项目仓库保持整洁，避免提交不必要的文件，并提高团队协作效率。
