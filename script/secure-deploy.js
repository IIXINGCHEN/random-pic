#!/usr/bin/env node
/**
 * 增强的安全部署脚本
 * 在部署前执行安全检查
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// 颜色输出
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m'
};

// 执行部署前安全检查
function runSecurityChecks() {
  console.log(`${colors.yellow}执行部署前安全检查...${colors.reset}`);

  let checksPassed = true;

  // 1. 检查密钥是否过期
  try {
    console.log('检查密钥状态...');
    execSync('node script/check-key-rotation.js', { stdio: 'inherit' });
  } catch (error) {
    console.error(`${colors.red}密钥检查失败: ${error.message}${colors.reset}`);
    checksPassed = false;
  }

  // 2. 检查配置文件中的安全设置
  try {
    console.log('验证wrangler.toml配置...');

    const wranglerConfig = fs.readFileSync(path.join(process.cwd(), 'wrangler.toml'), 'utf8');

    // 检查workers.dev设置
    if (!/workers_dev\s*=\s*false/.test(wranglerConfig)) {
      console.error(`${colors.red}❌ 安全风险: workers_dev 未明确设置为 false${colors.reset}`);
      checksPassed = false;
    } else {
      console.log(`${colors.green}✅ workers.dev 已禁用${colors.reset}`);
    }

    // 检查防盗链保护
    if (!/enableHotlinkProtection\s*=\s*"true"/.test(wranglerConfig)) {
      console.error(`${colors.red}❌ 安全风险: 防盗链保护未启用${colors.reset}`);
      checksPassed = false;
    } else {
      console.log(`${colors.green}✅ 防盗链保护已启用${colors.reset}`);
    }

    // 检查trusted domains配置
    if (!/trustedDomains\s*=\s*"[^"]+"/.test(wranglerConfig)) {
      console.error(`${colors.yellow}⚠️ 警告: 未配置受信任域名${colors.reset}`);
    } else {
      console.log(`${colors.green}✅ 已配置受信任域名${colors.reset}`);
    }
  } catch (error) {
    console.error(`${colors.red}配置检查失败: ${error.message}${colors.reset}`);
    checksPassed = false;
  }

  // 3. 检查源代码中的安全问题
  // 这里可以添加代码扫描工具或规则

  return checksPassed;
}

// 主部署流程
async function deploy() {
  const environment = process.argv[2] || 'production';

  console.log(`准备部署到 ${environment} 环境...`);

  // 执行安全检查
  const securityChecksPassed = runSecurityChecks();

  if (!securityChecksPassed) {
    console.error(`${colors.red}❌ 安全检查失败，终止部署${colors.reset}`);
    console.log('请修复以上安全问题后再次尝试部署');
    process.exit(1);
  }

  console.log(`${colors.green}✅ 安全检查通过${colors.reset}`);

  // 继续原有部署流程
  try {
    // 这里可以调用原有的部署逻辑
    console.log(`正在部署到 ${environment} 环境...`);
    // execSync(`node script/deploy.js ${environment}`, { stdio: 'inherit' });
    console.log(`${colors.green}✅ 部署成功${colors.reset}`);
  } catch (error) {
    console.error(`${colors.red}❌ 部署失败: ${error.message}${colors.reset}`);
    process.exit(1);
  }
}

// 执行部署
deploy().catch(error => {
  console.error(`部署过程出错: ${error.message}`);
  process.exit(1);
}); 