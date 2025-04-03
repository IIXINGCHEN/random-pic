/**
 * CloudflareR2安全密钥生成工具
 * 
 * 此脚本用于生成 HMAC-SHA256 签名验证所需的强密钥，
 * 并提供测试功能验证密钥的有效性。
 * 
 * 使用方法:
 * - 基本用法: node key-generator.js
 * - 生成指定长度密钥: node key-generator.js --length 128
 * - 生成并测试签名: node key-generator.js --test
 * - 生成轮换密钥对: node key-generator.js --rotate
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// 配置选项
const DEFAULT_KEY_LENGTH = 64; // 默认密钥长度(字节)
const KEYS_DIR = path.join(__dirname, '../.keys'); // 密钥存储目录
const KEY_FILE = path.join(KEYS_DIR, 'keys.json'); // 密钥存储文件
const HISTORY_FILE = path.join(KEYS_DIR, 'key-history.json'); // 密钥历史记录

/**
 * 确保密钥存储目录存在
 */
function ensureKeyDirectory() {
    if (!fs.existsSync(KEYS_DIR)) {
        try {
            fs.mkdirSync(KEYS_DIR, { recursive: true, mode: 0o700 });
            console.log(`📁 创建密钥存储目录: ${KEYS_DIR}`);
        } catch (error) {
            console.error(`❌ 无法创建密钥目录: ${error.message}`);
            process.exit(1);
        }
    }
}

/**
 * 生成指定长度的随机密钥
 * @param {number} length - 密钥长度(字节)
 * @returns {Object} 不同格式的密钥
 */
function generateKey(length = DEFAULT_KEY_LENGTH) {
    const keyBytes = crypto.randomBytes(length);

    return {
        hex: keyBytes.toString('hex'),
        base64: keyBytes.toString('base64'),
        base64url: keyBytes.toString('base64url'),
        length: length,
        bits: length * 8,
        generatedAt: new Date().toISOString()
    };
}

/**
 * 使用密钥生成指定路径和时间戳的签名
 * @param {string} key - 十六进制或Base64格式的密钥
 * @param {string} path - 请求路径
 * @param {number} timestamp - 时间戳(毫秒)
 * @returns {string} 十六进制格式的签名
 */
function generateSignature(key, path, timestamp) {
    // 判断密钥格式并转换为Buffer
    let keyBuffer;
    if (/^[0-9a-f]+$/i.test(key)) {
        // 十六进制格式
        keyBuffer = Buffer.from(key, 'hex');
    } else {
        // 假定为Base64格式
        try {
            keyBuffer = Buffer.from(key, 'base64');
        } catch (e) {
            throw new Error('密钥格式无效，需要十六进制或Base64格式');
        }
    }

    // 构建签名数据
    const data = `${path}:${timestamp}`;

    // 计算HMAC-SHA256签名
    const hmac = crypto.createHmac('sha256', keyBuffer);
    hmac.update(data);
    return hmac.digest('hex');
}

/**
 * 测试密钥的签名验证功能
 * @param {string} key - 要测试的密钥
 */
function testSignatureVerification(key) {
    console.log('\n🧪 测试签名验证功能');
    console.log('===================================');

    // 测试数据
    const testPath = '/api/image';
    const testTimestamp = Date.now();

    try {
        // 生成签名
        const signature = generateSignature(key, testPath, testTimestamp);
        console.log(`✅ 签名生成成功: ${signature}`);

        // 验证示例URL
        const exampleUrl = `https://yourapi.com${testPath}`;
        console.log('\n📝 API请求示例:');
        console.log('-----------------------------------');
        console.log(`curl -X GET "${exampleUrl}"`);
        console.log(`  -H "x-timestamp: ${testTimestamp}"`);
        console.log(`  -H "x-signature: ${signature}"`);
        console.log('-----------------------------------');

        // 模拟验证
        const verifySignature = generateSignature(key, testPath, testTimestamp);
        const isValid = verifySignature === signature;
        console.log(`\n✅ 签名验证: ${isValid ? '通过' : '失败'}`);

        // 模拟过期验证(5分钟后)
        const expiredTimestamp = testTimestamp - (6 * 60 * 1000);
        const expiredSignature = generateSignature(key, testPath, expiredTimestamp);
        console.log(`\n⏰ 过期签名测试(6分钟前): ${expiredSignature}`);
        console.log(`   该签名在生产环境将被拒绝(超过5分钟时间容差)`);

        return isValid;
    } catch (error) {
        console.error(`❌ 签名测试失败: ${error.message}`);
        return false;
    }
}

/**
 * 显示密钥的特性和强度信息
 * @param {Object} keyData - 密钥数据对象
 */
function displayKeyStrength(keyData) {
    console.log('\n🔐 密钥特性与强度分析');
    console.log('===================================');
    console.log(`密钥长度: ${keyData.length} 字节 (${keyData.bits} 位)`);

    // 评估密钥强度
    let strengthLevel = '未知';
    let emoji = '❓';

    if (keyData.bits < 128) {
        strengthLevel = '弱';
        emoji = '⚠️';
    } else if (keyData.bits < 256) {
        strengthLevel = '中等';
        emoji = '🔔';
    } else if (keyData.bits < 512) {
        strengthLevel = '强';
        emoji = '👍';
    } else {
        strengthLevel = '非常强';
        emoji = '💪';
    }

    console.log(`密钥强度: ${emoji} ${strengthLevel}`);

    // 预计破解难度
    if (keyData.bits >= 256) {
        console.log('👌 安全性: 在可预见的未来无法通过暴力破解');
    } else if (keyData.bits >= 128) {
        console.log('👍 安全性: 对于大多数应用已足够安全');
    } else {
        console.log('⚠️ 警告: 不建议用于生产环境，请增加密钥长度');
    }
}

/**
 * 保存密钥到本地文件
 * @param {Object} keyData - 密钥数据
 * @param {boolean} isRotation - 是否为轮换操作
 */
function saveKey(keyData, isRotation = false) {
    try {
        // 确保密钥目录存在
        ensureKeyDirectory();

        // 保存当前密钥
        const keyInfo = {
            current: keyData,
            updatedAt: new Date().toISOString()
        };

        // 如果是轮换操作，保留上一个密钥
        if (isRotation && fs.existsSync(KEY_FILE)) {
            const previousData = JSON.parse(fs.readFileSync(KEY_FILE, 'utf8'));
            keyInfo.previous = previousData.current;
        }

        fs.writeFileSync(KEY_FILE, JSON.stringify(keyInfo, null, 2), 'utf8');
        // 设置严格的文件权限
        fs.chmodSync(KEY_FILE, 0o600);

        // 添加到历史记录
        let history = [];
        if (fs.existsSync(HISTORY_FILE)) {
            history = JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8'));
        }

        // 限制历史记录数量
        if (history.length >= 10) {
            history = history.slice(0, 9);
        }

        // 添加到历史记录的开头
        history.unshift({
            id: crypto.randomUUID(),
            generatedAt: keyData.generatedAt,
            length: keyData.length,
            bits: keyData.bits,
            type: isRotation ? 'rotation' : 'generation'
        });

        fs.writeFileSync(HISTORY_FILE, JSON.stringify(history, null, 2), 'utf8');
        // 设置严格的文件权限
        fs.chmodSync(HISTORY_FILE, 0o600);

        console.log(`\n✅ 密钥已${isRotation ? '轮换并' : ''}保存到 ${KEY_FILE}`);
        console.log(`📜 密钥历史记录已更新 ${HISTORY_FILE}`);

        // 提示设置密钥文件权限
        console.log('\n⚠️ 重要: 密钥文件已自动设置为仅所有者可读写 (chmod 600)');
        console.log(`   密钥目录: ${KEYS_DIR}`);
    } catch (error) {
        console.error(`❌ 无法保存密钥: ${error.message}`);
    }
}

/**
 * 生成Wrangler设置密钥的命令
 * @param {Object} keyData - 密钥数据
 */
function generateWranglerCommands(keyData) {
    console.log('\n🚀 Cloudflare Wrangler 部署命令');
    console.log('===================================');
    console.log('# 设置主密钥');
    console.log('wrangler secret put SIGNATURE_SECRET_KEY');
    console.log(`# 然后粘贴此值: ${keyData.hex}`);

    console.log('\n# 记录密钥版本和轮换日期');
    console.log('wrangler secret put KEY_VERSION');
    console.log('# 输入版本号, 例如: 1');

    console.log('\nwrangler secret put KEY_ROTATION_DATE');
    console.log(`# 输入今天的日期: ${new Date().toISOString().split('T')[0]}`);

    // 如果有前一个密钥，则显示设置命令
    if (fs.existsSync(KEY_FILE)) {
        try {
            const keyFile = JSON.parse(fs.readFileSync(KEY_FILE, 'utf8'));
            if (keyFile.previous) {
                console.log('\n# 设置前一个密钥(用于过渡期验证)');
                console.log('wrangler secret put SIGNATURE_SECRET_KEY_PREVIOUS');
                console.log(`# 然后粘贴此值: ${keyFile.previous.hex}`);
            }
        } catch (e) {
            // 忽略文件读取错误
        }
    }
}

/**
 * 生成客户端示例代码
 * @param {Object} keyData - 密钥数据
 */
function generateClientExamples(keyData) {
    console.log('\n📱 客户端调用示例');
    console.log('===================================');

    // JavaScript客户端示例
    console.log('JavaScript (Browser):');
    console.log('```javascript');
    console.log(`// 注意: 客户端代码不应包含服务器密钥
// 这些调用应通过您的应用后端进行

async function callImageAPI(path = '/api/image') {
  const timestamp = Date.now();
  
  // 在实际应用中，签名应由服务器端生成
  // 这里仅作为示例，实际环境中不要在前端计算签名
  
  const response = await fetch(\`https://yourapi.com\${path}\`, {
    method: 'GET',
    headers: {
      'x-timestamp': timestamp,
      'x-signature': '由服务器端生成的签名', // 正确实现时应由后端提供
    }
  });
  
  if (!response.ok) {
    throw new Error(\`API错误: \${response.status}\`);
  }
  
  return response;
}
`);
    console.log('```');

    // Node.js客户端示例
    console.log('\nNode.js (服务器):');
    console.log('```javascript');
    console.log(`const crypto = require('crypto');

// 重要: 将密钥安全地存储在环境变量或密钥管理系统中
const SECRET_KEY = process.env.API_SECRET_KEY; // 不要硬编码密钥

function generateSignature(path, timestamp) {
  const data = \`\${path}:\${timestamp}\`;
  const hmac = crypto.createHmac('sha256', Buffer.from(SECRET_KEY, 'hex'));
  hmac.update(data);
  return hmac.digest('hex');
}

async function callSecureAPI(path = '/api/image') {
  const timestamp = Date.now();
  const signature = generateSignature(path, timestamp);
  
  const response = await fetch(\`https://yourapi.com\${path}\`, {
    method: 'GET',
    headers: {
      'x-timestamp': timestamp,
      'x-signature': signature
    }
  });
  
  if (!response.ok) {
    throw new Error(\`API错误: \${response.status}\`);
  }
  
  return response;
}
`);
    console.log('```');
}

/**
 * 主函数：解析命令行参数并执行相应操作
 */
function main() {
    // 确保密钥目录存在
    ensureKeyDirectory();

    const args = process.argv.slice(2);
    let keyLength = DEFAULT_KEY_LENGTH;
    let testMode = false;
    let rotateMode = false;

    // 解析命令行参数
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--length' && args[i + 1]) {
            keyLength = parseInt(args[i + 1], 10);
            i++; // 跳过下一个参数
        } else if (args[i] === '--test') {
            testMode = true;
        } else if (args[i] === '--rotate') {
            rotateMode = true;
        } else if (args[i] === '--help') {
            console.log(`
CloudflareR2安全密钥生成工具

选项:
  --length <字节>  指定密钥长度(字节), 默认: ${DEFAULT_KEY_LENGTH}
  --test           生成密钥并测试签名功能
  --rotate         生成新密钥并保留前一个密钥(轮换)
  --help           显示帮助信息
      `);
            return;
        }
    }

    if (keyLength < 32) {
        console.warn('⚠️ 警告: 密钥长度低于推荐的最小值(32字节/256位)');
        console.warn('   为了生产环境安全, 请使用更长的密钥');
    }

    console.log('🔑 CloudflareR2安全密钥生成器');
    console.log('===================================');
    console.log(`生成${rotateMode ? '并轮换' : ''}密钥 (${keyLength} 字节 / ${keyLength * 8} 位)...`);

    // 生成密钥
    const keyData = generateKey(keyLength);

    // 显示密钥
    console.log('\n生成的密钥:');
    console.log('-----------------------------------');
    console.log(`十六进制 (推荐): ${keyData.hex}`);
    console.log(`Base64: ${keyData.base64}`);
    console.log(`Base64URL: ${keyData.base64url}`);
    console.log('-----------------------------------');

    // 分析密钥强度
    displayKeyStrength(keyData);

    // 测试签名验证
    if (testMode) {
        testSignatureVerification(keyData.hex);
    }

    // 保存密钥
    saveKey(keyData, rotateMode);

    // 生成Wrangler命令
    generateWranglerCommands(keyData);

    // 生成客户端示例
    generateClientExamples(keyData);

    console.log('\n🎉 完成!');
}

// 执行主函数
main(); 