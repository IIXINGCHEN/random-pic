#!/bin/bash
# Random Picture Service 部署脚本
# 用法: ./deploy.sh [环境]

set -e  # 任何命令失败立即退出

# 默认环境为生产
ENVIRONMENT=${1:-"production"}
echo "准备部署到 $ENVIRONMENT 环境..."

# 检查pnpm依赖
echo "检查pnpm依赖..."
if ! command -v pnpm &> /dev/null; then
    echo "错误: pnpm 未安装. 请运行 'npm install -g pnpm'"
    exit 1
fi

# 检查wrangler依赖
echo "检查wrangler依赖..."
if ! command -v wrangler &> /dev/null; then
    echo "错误: wrangler 未安装. 请运行 'pnpm add -g wrangler'"
    exit 1
fi

# 安装依赖
echo "安装项目依赖..."
pnpm install

# 运行测试
echo "运行测试..."
pnpm test || { echo "测试失败！中止部署。"; exit 1; }

# 生成版本号（使用时间戳和git commit hash）
VERSION=$(date +"%Y%m%d%H%M%S")-$(git rev-parse --short HEAD 2>/dev/null || echo "nogit")
echo "部署版本: $VERSION"

# 备份配置文件
echo "备份配置文件..."
cp wrangler.toml wrangler.toml.backup

# 写入版本号到配置
if grep -q "\[vars\]" wrangler.toml; then
    sed -i.bak "/\[vars\]/a version = \"$VERSION\"" wrangler.toml
else
    echo -e "\n[vars]\nversion = \"$VERSION\"" >> wrangler.toml
fi

# 部署到指定环境
echo "部署到 $ENVIRONMENT 环境..."
if [ "$ENVIRONMENT" == "production" ]; then
    pnpm exec wrangler deploy --env production
else
    pnpm exec wrangler deploy --env ${ENVIRONMENT}
fi

# 部署结果验证
if [ $? -eq 0 ]; then
    echo "✅ 部署成功！"
    echo "访问以下URL测试服务:"
    echo "- 水平图片: https://hrandom-pic.example.com"
    echo "- 垂直图片: https://vrandom-pic.example.com"
    echo "- 图片数量API: https://api-hrandom-pic.example.com"
else
    echo "❌ 部署失败！恢复配置..."
    # 恢复配置文件
    mv wrangler.toml.backup wrangler.toml
    exit 1
fi

# 恢复配置文件
mv wrangler.toml.bak wrangler.toml

echo "部署完成！版本号: $VERSION" 
