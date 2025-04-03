@echo off
:: Random Picture Service 部署脚本
:: 用法: deploy.bat [环境]

setlocal enabledelayedexpansion

:: 默认环境为生产
set ENVIRONMENT=%1
if "%ENVIRONMENT%"=="" set ENVIRONMENT=production
echo 准备部署到 %ENVIRONMENT% 环境...

:: 检查pnpm依赖
echo 检查pnpm依赖...
where pnpm >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo 错误: pnpm 未安装. 请运行 'npm install -g pnpm'
    exit /b 1
)

:: 检查wrangler依赖
echo 检查wrangler依赖...
where wrangler >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo 错误: wrangler 未安装. 请运行 'pnpm add -g wrangler'
    exit /b 1
)

:: 安装依赖
echo 安装项目依赖...
call pnpm install

:: 运行测试
echo 运行测试...
call pnpm test
if %ERRORLEVEL% neq 0 (
    echo 测试失败！中止部署。
    exit /b 1
)

:: 生成版本号
for /f "tokens=2 delims==" %%a in ('wmic os get localdatetime /value') do set datetime=%%a
set VERSION=%datetime:~0,14%

:: 尝试获取Git哈希
git rev-parse --short HEAD >nul 2>nul
if %ERRORLEVEL% equ 0 (
    for /f %%i in ('git rev-parse --short HEAD') do set GIT_HASH=%%i
    set VERSION=%VERSION%-%GIT_HASH%
) else (
    set VERSION=%VERSION%-nogit
)

echo 部署版本: %VERSION%

:: 备份配置文件
echo 备份配置文件...
copy wrangler.toml wrangler.toml.backup

:: 部署到指定环境
echo 部署到 %ENVIRONMENT% 环境...
if "%ENVIRONMENT%"=="production" (
    call pnpm exec wrangler deploy --env production
) else (
    call pnpm exec wrangler deploy --env %ENVIRONMENT%
)

:: 部署结果验证
if %ERRORLEVEL% equ 0 (
    echo ✅ 部署成功！
    echo 访问以下URL测试服务:
    echo - 水平图片: https://hrandom-pic.onani.cn
    echo - 垂直图片: https://vrandom-pic.onani.cn
    echo - 图片数量API: https://api-hrandom-pic.onani.cn
) else (
    echo ❌ 部署失败！恢复配置...
    :: 恢复配置文件
    copy wrangler.toml.backup wrangler.toml
    exit /b 1
)

:: 清理备份
del wrangler.toml.backup

echo 部署完成！版本号: %VERSION% 