#!/usr/bin/env node
/**
 * 密钥轮换检查脚本
 * 检查密钥是否接近轮换期限，并发送提醒
 */

const fs = require('fs');
const path = require('path');

// 安全配置
const MAX_KEY_AGE_DAYS = 90; // 密钥最长使用期限(天)
const KEYS_DIR = path.join(__dirname, '../.keys');
const HISTORY_FILE = path.join(KEYS_DIR, 'key-history.json');

// 颜色输出
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  green: '\x1b[32m'
};

function checkKeyRotation() {
  console.log('🔑 检查密钥轮换状态...');
  
  // 确保密钥历史文件存在
  if (!fs.existsSync(HISTORY_FILE)) {
    console.log('❌ 密钥历史文件不存在。请先生成密钥。');
    return;
  }
  
  try {
    // 读取密钥历史
    const history = JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8'));
    
    if (history.length === 0) {
      console.log('❌ 密钥历史为空。请先生成密钥。');
      return;
    }
    
    // 获取最新密钥
    const latestKey = history[0];
    const generatedDate = new Date(latestKey.generatedAt);
    const now = new Date();
    
    // 计算密钥年龄(天)
    const ageInDays = Math.floor((now - generatedDate) / (1000 * 60 * 60 * 24));
    
    console.log(`当前密钥生成于: ${generatedDate.toLocaleString()}`);
    console.log(`密钥年龄: ${ageInDays} 天`);
    
    // 根据密钥年龄输出状态
    if (ageInDays >= MAX_KEY_AGE_DAYS) {
      console.log(`${colors.red}⚠️ 警告: 密钥已过期 (${ageInDays} 天)${colors.reset}`);
      console.log(`${colors.red}请立即执行密钥轮换: node script/key-generator.js --rotate --test${colors.reset}`);
    } else if (ageInDays >= MAX_KEY_AGE_DAYS * 0.8) {
      console.log(`${colors.yellow}⚠️ 警告: 密钥即将过期 (${ageInDays} 天)${colors.reset}`);
      console.log(`${colors.yellow}请在 ${MAX_KEY_AGE_DAYS - ageInDays} 天内执行密钥轮换${colors.reset}`);
    } else {
      console.log(`${colors.green}✅ 密钥状态良好${colors.reset}`);
      console.log(`下次轮换时间: ${MAX_KEY_AGE_DAYS - ageInDays} 天后`);
    }
  } catch (error) {
    console.error(`❌ 检查密钥轮换时出错: ${error.message}`);
  }
}

// 执行检查
checkKeyRotation(); 