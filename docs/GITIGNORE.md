# .gitignore 说明文档

本项目的 `.gitignore` 文件经过精心设计，确保只提交必要的源代码文件，避免提交构建产物、临时文件和敏感信息。

## 文件结构

```
.gitignore          # 项目根目录的 gitignore
docs/.gitignore     # 文档目录专用的 gitignore
```

## 忽略规则分类

### 1. Go 语言相关

#### 编译产物
- `*.exe`, `*.dll`, `*.so`, `*.dylib` - 编译生成的二进制文件
- `bin/` - 二进制文件目录
- `*.test` - 测试二进制文件

#### 测试和性能分析
- `*.out`, `*.prof`, `*.cov` - 覆盖率和性能分析文件
- `*.pprof` - 性能分析文件
- `coverage.html`, `coverage.xml` - 覆盖率报告
- `*.bench` - 基准测试结果

#### Go 工具
- `go.work` - Go 工作区文件
- `vendor/` - 依赖目录（如果使用 vendor 模式）

### 2. 文档相关

#### VitePress
- `docs/.vitepress/dist/` - 构建输出
- `docs/.vitepress/cache/` - 构建缓存
- `docs/node_modules/` - Node.js 依赖
- `docs/package-lock.json` - 包管理器锁文件

#### 临时文件
- `docs/.temp/` - 临时文件
- `docs/.cache/` - 缓存文件

### 3. IDE 和编辑器

#### JetBrains 系列
- `.idea/` - IntelliJ IDEA 配置
- `*.iml` - IntelliJ 模块文件

#### Visual Studio Code
- `.vscode/` - VS Code 配置

#### 其他编辑器
- `*.swp`, `*.swo` - Vim 临时文件
- `*.sublime-*` - Sublime Text 配置
- `.atom/` - Atom 编辑器配置

### 4. 操作系统文件

#### macOS
- `.DS_Store` - Finder 元数据
- `.AppleDouble` - 资源分叉
- `.Spotlight-V100` - Spotlight 索引

#### Windows
- `Thumbs.db` - 缩略图缓存
- `desktop.ini` - 文件夹配置

#### Linux
- `.directory` - KDE 文件夹配置

### 5. 项目特定文件

#### 编译产物
- `cvss-cli` - CLI 工具二进制文件
- `examples/*/main` - 示例程序编译结果

#### 测试数据
- `testdata/generated/` - 生成的测试数据
- `test-vectors.json` - 测试向量文件

#### 配置文件
- `config.local.*` - 本地配置文件
- `.env*` - 环境变量文件

### 6. 安全相关

#### 证书和密钥
- `*.pem`, `*.key`, `*.crt` - 证书文件
- `secrets/` - 密钥目录

#### 扫描结果
- `gosec-report.json` - 安全扫描报告
- `*.sarif` - 静态分析结果

### 7. 部署相关

#### Docker
- `Dockerfile.local` - 本地 Docker 配置
- `docker-compose.override.yml` - Docker Compose 覆盖配置

#### Kubernetes
- `k8s-local/` - 本地 K8s 配置
- `*.kubeconfig` - Kubernetes 配置

### 8. 开发工具

#### 调试工具
- `debug`, `__debug_bin` - 调试二进制文件
- `dlv` - Delve 调试器

#### 热重载
- `.air.toml` - Air 配置文件
- `tmp/` - 临时目录

## 最佳实践

### 1. 不要忽略的文件

以下文件应该被提交到版本控制：

```bash
# 源代码
pkg/
cmd/
examples/

# 配置文件
go.mod
go.sum
.gitignore
README.md

# 文档源文件
docs/*.md
docs/.vitepress/config.js
docs/package.json

# CI/CD 配置
.github/workflows/
```

### 2. 检查忽略规则

使用以下命令检查文件是否被正确忽略：

```bash
# 查看所有未跟踪的文件
git status --porcelain

# 检查特定文件是否被忽略
git check-ignore -v <file-path>

# 查看所有被忽略的文件
git status --ignored
```

### 3. 临时包含被忽略的文件

如果需要临时提交被忽略的文件：

```bash
# 强制添加被忽略的文件
git add -f <file-path>
```

### 4. 更新 .gitignore

添加新的忽略规则后：

```bash
# 清除已跟踪但现在被忽略的文件
git rm -r --cached <file-or-directory>
git commit -m "Remove files now ignored"
```

## 维护指南

### 定期检查

1. **检查是否有不应该被忽略的文件**
   ```bash
   git status --ignored
   ```

2. **检查是否有应该被忽略但没有被忽略的文件**
   ```bash
   git status
   ```

3. **验证构建产物被正确忽略**
   ```bash
   make build
   git status  # 不应该显示新的二进制文件
   ```

### 更新规则

当项目结构发生变化时，及时更新 `.gitignore`：

- 添加新的构建工具时，忽略其产生的文件
- 添加新的开发工具时，忽略其配置文件
- 添加新的测试框架时，忽略其输出文件

## 相关文档

- [Git 官方文档 - gitignore](https://git-scm.com/docs/gitignore)
- [GitHub gitignore 模板](https://github.com/github/gitignore)
- [Go 项目 gitignore 最佳实践](https://github.com/github/gitignore/blob/main/Go.gitignore)
