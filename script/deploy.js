#!/usr/bin/env node
// Random Picture Service 部署脚本
// 用法: node deploy.js [环境]

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// 定义颜色输出
const colors = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
};

// 日志函数
const log = {
    info: (msg) => console.log(`${colors.blue}[INFO]${colors.reset} ${msg}`),
    success: (msg) => console.log(`${colors.green}[SUCCESS]${colors.reset} ${msg}`),
    error: (msg) => console.log(`${colors.red}[ERROR]${colors.reset} ${msg}`),
    warn: (msg) => console.log(`${colors.yellow}[WARNING]${colors.reset} ${msg}`),
};

// 获取环境参数
const environment = process.argv[2] || 'production';
log.info(`准备部署到 ${colors.cyan}${environment}${colors.reset} 环境...`);

try {
    // 检查pnpm依赖
    log.info('检查依赖...');
    try {
        execSync('pnpm --version', { stdio: 'ignore' });
    } catch (error) {
        log.error('pnpm 未安装. 请运行 npm install -g pnpm');
        process.exit(1);
    }

    // 检查wrangler依赖
    try {
        execSync('npx wrangler --version', { stdio: 'ignore' });
    } catch (error) {
        log.error('wrangler 未安装. 请运行 pnpm add -g wrangler');
        process.exit(1);
    }

    // 安装依赖
    log.info('安装项目依赖...');
    execSync('pnpm install', { stdio: 'inherit' });

    // 运行测试
    log.info('运行测试...');
    try {
        execSync('pnpm test', { stdio: 'inherit' });
    } catch (error) {
        log.error('测试失败！中止部署。');
        process.exit(1);
    }

    // 生成版本号
    const timestamp = new Date().toISOString().replace(/[-:T.Z]/g, '');
    let gitHash = 'nogit';
    try {
        gitHash = execSync('git rev-parse --short HEAD').toString().trim();
    } catch (error) {
        log.warn('无法获取 Git hash，使用默认值。');
    }
    const version = `${timestamp}-${gitHash}`;
    log.info(`部署版本: ${colors.magenta}${version}${colors.reset}`);

    // 备份配置文件
    log.info('备份配置文件...');
    const wranglerPath = path.join(process.cwd(), 'wrangler.toml');
    const backupPath = path.join(process.cwd(), 'wrangler.toml.backup');
    fs.copyFileSync(wranglerPath, backupPath);

    // 部署
    log.info(`部署到 ${environment} 环境...`);
    const deployCommand = `pnpm exec wrangler deploy ${environment !== 'production' ? `--env ${environment}` : ''}`;
    execSync(deployCommand, { stdio: 'inherit' });

    // 部署成功
    log.success('部署成功！');
    log.info('访问以下URL测试服务:');
    log.info(`- 水平图片: ${colors.cyan}https://hrandom-pic.example.com${colors.reset}`);
    log.info(`- 垂直图片: ${colors.cyan}https://vrandom-pic.example.com${colors.reset}`);
    log.info(`- 图片数量API: ${colors.cyan}https://api-hrandom-pic.example.com${colors.reset}`);

    // 恢复配置文件
    fs.copyFileSync(backupPath, wranglerPath);
    fs.unlinkSync(backupPath);

    log.info(`部署完成！版本号: ${colors.magenta}${version}${colors.reset}`);
} catch (error) {
    log.error(`部署过程中发生错误: ${error.message}`);

    // 尝试恢复配置
    const wranglerPath = path.join(process.cwd(), 'wrangler.toml');
    const backupPath = path.join(process.cwd(), 'wrangler.toml.backup');
    if (fs.existsSync(backupPath)) {
        log.warn('恢复配置文件...');
        fs.copyFileSync(backupPath, wranglerPath);
        fs.unlinkSync(backupPath);
    }

    process.exit(1);
} 
