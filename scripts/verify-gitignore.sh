#!/bin/bash

# 验证 .gitignore 规则的脚本
# 用于确保重要文件没有被忽略，不重要文件被正确忽略

set -e

echo "🔍 验证 .gitignore 规则..."

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 计数器
PASSED=0
FAILED=0

# 检查函数：文件应该被忽略
check_ignored() {
    local file="$1"
    local description="$2"
    
    if git check-ignore "$file" >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} $description: $file (正确忽略)"
        ((PASSED++))
    else
        echo -e "${RED}✗${NC} $description: $file (应该被忽略但没有)"
        ((FAILED++))
    fi
}

# 检查函数：文件不应该被忽略
check_not_ignored() {
    local file="$1"
    local description="$2"
    
    if ! git check-ignore "$file" >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} $description: $file (正确包含)"
        ((PASSED++))
    else
        echo -e "${RED}✗${NC} $description: $file (不应该被忽略但被忽略了)"
        ((FAILED++))
    fi
}

# 创建临时测试文件
create_test_file() {
    local file="$1"
    local dir=$(dirname "$file")
    
    if [ "$dir" != "." ]; then
        mkdir -p "$dir"
    fi
    touch "$file"
}

# 清理测试文件
cleanup_test_file() {
    local file="$1"
    local dir=$(dirname "$file")
    
    rm -f "$file"
    if [ "$dir" != "." ] && [ -d "$dir" ] && [ -z "$(ls -A "$dir")" ]; then
        rmdir "$dir"
    fi
}

echo "📋 测试应该被忽略的文件..."

# Go 编译产物
test_files=(
    "main.exe:Go 可执行文件"
    "test.dll:Go 动态库"
    "app.so:Go 共享库"
    "program.dylib:Go macOS 库"
    "test.test:Go 测试二进制"
    "coverage.out:Go 覆盖率文件"
    "cpu.prof:Go 性能分析文件"
    "mem.pprof:Go 内存分析文件"
)

for item in "${test_files[@]}"; do
    IFS=':' read -r file desc <<< "$item"
    create_test_file "$file"
    check_ignored "$file" "$desc"
    cleanup_test_file "$file"
done

# 文档构建产物
doc_files=(
    "docs/.vitepress/dist/index.html:VitePress 构建输出"
    "docs/.vitepress/cache/deps.json:VitePress 缓存"
    "docs/node_modules/package/index.js:Node.js 依赖"
    "docs/package-lock.json:NPM 锁文件"
)

for item in "${doc_files[@]}"; do
    IFS=':' read -r file desc <<< "$item"
    create_test_file "$file"
    check_ignored "$file" "$desc"
    cleanup_test_file "$file"
done

# IDE 配置文件
ide_files=(
    ".idea/workspace.xml:IntelliJ IDEA 配置"
    ".vscode/settings.json:VS Code 配置"
    "test.swp:Vim 临时文件"
    ".DS_Store:macOS 系统文件"
    "Thumbs.db:Windows 缩略图"
)

for item in "${ide_files[@]}"; do
    IFS=':' read -r file desc <<< "$item"
    create_test_file "$file"
    check_ignored "$file" "$desc"
    cleanup_test_file "$file"
done

# 项目特定文件
project_files=(
    "cvss-cli:CLI 工具二进制"
    "examples/basic/main:示例程序二进制"
    "testdata/generated/test.json:生成的测试数据"
    "config.local.yaml:本地配置文件"
    ".env:环境变量文件"
    "secrets/api.key:密钥文件"
)

for item in "${project_files[@]}"; do
    IFS=':' read -r file desc <<< "$item"
    create_test_file "$file"
    check_ignored "$file" "$desc"
    cleanup_test_file "$file"
done

echo ""
echo "📋 测试不应该被忽略的文件..."

# 检查重要的源代码文件
important_files=(
    "go.mod:Go 模块文件"
    "go.sum:Go 依赖锁文件"
    "README.md:项目说明文件"
    ".gitignore:Git 忽略规则"
    "Makefile:构建脚本"
)

for item in "${important_files[@]}"; do
    IFS=':' read -r file desc <<< "$item"
    if [ -f "$file" ]; then
        check_not_ignored "$file" "$desc"
    else
        echo -e "${YELLOW}⚠${NC} $desc: $file (文件不存在，跳过检查)"
    fi
done

# 检查源代码目录
source_dirs=(
    "pkg/cvss/cvss3x.go:核心源代码"
    "pkg/parser/cvss3x_parser.go:解析器源代码"
    "pkg/vector/vector.go:向量接口"
    "cmd/cvss-cli/main.go:CLI 工具源代码"
    "examples/01_basic/main.go:示例源代码"
)

for item in "${source_dirs[@]}"; do
    IFS=':' read -r file desc <<< "$item"
    if [ -f "$file" ]; then
        check_not_ignored "$file" "$desc"
    else
        echo -e "${YELLOW}⚠${NC} $desc: $file (文件不存在，跳过检查)"
    fi
done

# 检查文档源文件
doc_source_files=(
    "docs/index.md:文档首页"
    "docs/.vitepress/config.js:VitePress 配置"
    "docs/package.json:文档依赖配置"
    "docs/api/index.md:API 文档"
)

for item in "${doc_source_files[@]}"; do
    IFS=':' read -r file desc <<< "$item"
    if [ -f "$file" ]; then
        check_not_ignored "$file" "$desc"
    else
        echo -e "${YELLOW}⚠${NC} $desc: $file (文件不存在，跳过检查)"
    fi
done

# 检查 CI/CD 配置
cicd_files=(
    ".github/workflows/go-test.yml:Go 测试工作流"
    ".github/workflows/docs.yml:文档部署工作流"
)

for item in "${cicd_files[@]}"; do
    IFS=':' read -r file desc <<< "$item"
    if [ -f "$file" ]; then
        check_not_ignored "$file" "$desc"
    else
        echo -e "${YELLOW}⚠${NC} $desc: $file (文件不存在，跳过检查)"
    fi
done

echo ""
echo "📊 验证结果:"
echo -e "  ${GREEN}通过: $PASSED${NC}"
echo -e "  ${RED}失败: $FAILED${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 所有 .gitignore 规则验证通过！${NC}"
    exit 0
else
    echo -e "${RED}❌ 发现 $FAILED 个问题，请检查 .gitignore 配置${NC}"
    exit 1
fi
