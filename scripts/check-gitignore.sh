#!/bin/bash

# 简单的 .gitignore 验证脚本

echo "🔍 检查 .gitignore 规则..."

# 创建测试文件并检查是否被忽略
test_ignored() {
    local file="$1"
    local desc="$2"
    
    touch "$file"
    if git check-ignore "$file" >/dev/null 2>&1; then
        echo "✓ $desc: $file (正确忽略)"
        rm -f "$file"
        return 0
    else
        echo "✗ $desc: $file (应该被忽略)"
        rm -f "$file"
        return 1
    fi
}

# 检查重要文件是否被错误忽略
test_not_ignored() {
    local file="$1"
    local desc="$2"
    
    if [ -f "$file" ]; then
        if git check-ignore "$file" >/dev/null 2>&1; then
            echo "✗ $desc: $file (不应该被忽略)"
            return 1
        else
            echo "✓ $desc: $file (正确包含)"
            return 0
        fi
    else
        echo "⚠ $desc: $file (文件不存在)"
        return 0
    fi
}

echo ""
echo "📋 测试应该被忽略的文件..."

# 测试编译产物
test_ignored "test.exe" "Go 可执行文件"
test_ignored "test.test" "Go 测试二进制"
test_ignored "coverage.out" "覆盖率文件"

# 测试文档构建产物
mkdir -p docs/.vitepress/dist
test_ignored "docs/.vitepress/dist/index.html" "VitePress 构建输出"
rmdir docs/.vitepress/dist 2>/dev/null || true

mkdir -p docs/node_modules
test_ignored "docs/node_modules/test.js" "Node.js 依赖"
rmdir docs/node_modules 2>/dev/null || true

# 测试系统文件
test_ignored ".DS_Store" "macOS 系统文件"
test_ignored "Thumbs.db" "Windows 缩略图"

# 测试 IDE 文件
mkdir -p .idea
test_ignored ".idea/workspace.xml" "IntelliJ IDEA 配置"
rmdir .idea 2>/dev/null || true

echo ""
echo "📋 测试不应该被忽略的重要文件..."

# 测试源代码文件
test_not_ignored "go.mod" "Go 模块文件"
test_not_ignored "README.md" "项目说明"
test_not_ignored ".gitignore" "Git 忽略规则"

# 测试源代码
test_not_ignored "pkg/cvss/cvss3x.go" "核心源代码"
test_not_ignored "pkg/parser/cvss3x_parser.go" "解析器源代码"

# 测试文档源文件
test_not_ignored "docs/index.md" "文档首页"
test_not_ignored "docs/package.json" "文档配置"

echo ""
echo "✅ .gitignore 验证完成"
