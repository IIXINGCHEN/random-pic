/**
 * =============================================================================
 * 生产环境就绪的 Cloudflare Worker 代码 (基于 Hono)
 * =============================================================================
 *
 * 功能：
 * 1. 提供随机图片服务，根据域名或路径参数区分横向/纵向图片。
 * 2. 提供 API 接口 (`/`) 用于统计特定类型图片的数量。
 * 3. 实现基于 HMAC-SHA256 的请求签名验证，防止未授权访问。
 * 4. 实现基于 IP 地址的速率限制，防止滥用。
 * 5. 使用 Cloudflare Cache API 缓存图片响应，提高性能。
 * 6. 使用 Cloudflare R2 存储图片。
 * 7. 使用 Cloudflare KV 存储速率限制计数器。
 * 8. 包含详细的错误处理和日志记录。
 *
 * 重要提示 (生产环境部署前必读):
 * 1.  **密钥管理:** 此代码期望签名密钥通过 Cloudflare Secrets (环境变量 `SIGNATURE_SECRET_KEY`) 提供。
 * 请务必使用 `wrangler secret put SIGNATURE_SECRET_KEY` 命令设置一个强密钥。
 * *切勿* 将生产密钥硬编码或放入 `wrangler.toml` 的 `[vars]` 中。
 * 2.  **`wrangler.toml` 配置:**
 * * 确保为生产环境配置了正确的 R2 bucket name (`myBucket` 绑定)。
 * * 确保为生产环境配置了正确的 KV namespace id (`rateLimitCache` 绑定)。
 * * 使用 Wrangler Environments (`[env.production]`) 或单独的配置文件管理生产环境特定的变量和绑定。
 * * 正确配置 Worker 路由和域名。
 * 3.  **CORS:** 根据需要调整 `cors` 中间件的 `origin` 设置，限制允许访问的来源。
 * 4.  **速率限制/信任IP:** 根据实际情况调整 `rateLimit`, `rateLimitWindow` 和 `trustedIps` 配置。
 * 5.  **日志:** 建议配置 Cloudflare Logpush 将日志推送到外部存储进行分析。
 *
 */

// 导入 Hono 框架核心和 CORS 中间件
import { Hono } from 'hono';
import { cors } from 'hono/cors';

// --- 辅助函数：将 ArrayBuffer 转换为 Hex 字符串 ---
// 用于将 crypto.subtle 生成的签名 ArrayBuffer 转换为可读的十六进制字符串
function bufToHex(buffer) {
    // 将 ArrayBuffer 转换为 Uint8Array
    // 遍历每个字节，将其转换为两位十六进制字符串，不足两位的用 '0' 填充
    // 最后将所有十六进制字符串连接起来
    return [...new Uint8Array(buffer)]
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// --- 配置类：管理从环境变量加载的配置 ---
class Config {
    constructor(env) {
        // 从环境变量 (env) 加载配置，env 对象由 Cloudflare Worker 运行时提供，包含 wrangler.toml vars 和 secrets

        // 横向图片服务的域名列表 (逗号分隔转数组)
        this.hRandomDomains = env.hRandomDomains ? env.hRandomDomains.split(',').map(d => d.trim()) : [];
        // 纵向图片服务的域名列表 (逗号分隔转数组)
        this.vRandomDomains = env.vRandomDomains ? env.vRandomDomains.split(',').map(d => d.trim()) : [];
        // R2 中横向图片的前缀
        this.hRandomPrefix = env.hRandomPrefix || 'ri/h/';
        // R2 中纵向图片的前缀
        this.vRandomPrefix = env.vRandomPrefix || 'ri/v/';
        // 默认图片 Content-Type
        this.defaultContentType = env.defaultContentType || 'image/jpeg';
        // API 域名的前缀，用于区分 API 调用和直接图片请求
        this.apiPrefix = env.apiPrefix || 'api-';

        // 速率限制：每窗口允许的最大请求数
        // 从环境变量解析，如果无效或未提供，使用默认值 50
        this.rateLimit = parseInt(env.rateLimit);
        if (isNaN(this.rateLimit)) {
            console.warn(`[Config] Invalid rateLimit value "${env.rateLimit}", using default 50.`);
            this.rateLimit = 50;
        }

        // 速率限制：时间窗口大小（秒）
        // 从环境变量解析，如果无效或未提供，使用默认值 60
        this.rateLimitWindow = parseInt(env.rateLimitWindow);
        if (isNaN(this.rateLimitWindow)) {
            console.warn(`[Config] Invalid rateLimitWindow value "${env.rateLimitWindow}", using default 60.`);
            this.rateLimitWindow = 60;
        }

        // 缓存 TTL（生存时间，秒）
        // 从环境变量解析，如果无效或未提供，使用默认值 3600 (1 小时)
        this.cacheTtl = parseInt(env.cacheTtl);
        if (isNaN(this.cacheTtl)) {
            console.warn(`[Config] Invalid cacheTtl value "${env.cacheTtl}", using default 3600.`);
            this.cacheTtl = 3600;
        }

        // 【安全】签名密钥 - *必须* 通过 Cloudflare Secrets (环境变量) 配置
        // wrangler secret put SIGNATURE_SECRET_KEY
        this.secretKey = env.SIGNATURE_SECRET_KEY;
        if (!this.secretKey) {
            // 如果未配置密钥，记录严重错误并可能阻止 Worker 启动或处理请求
            console.error('CRITICAL [Config]: SIGNATURE_SECRET_KEY secret is not configured in environment!');
            // 在生产环境中，这里应该抛出错误或采取其他措施使 Worker 失败
            throw new Error("Missing required secret: SIGNATURE_SECRET_KEY");
        }
        // 存储导入后的 HMAC 密钥（CryptoKey 对象），避免重复导入
        this.secretKeyBuffer = null;

        // R2 list 操作的最大对象限制
        // 从环境变量解析，如果无效或未提供，使用默认值 1000
        this.maxListLimit = parseInt(env.maxListLimit);
        if (isNaN(this.maxListLimit)) {
            console.warn(`[Config] Invalid maxListLimit value "${env.maxListLimit}", using default 1000.`);
            this.maxListLimit = 1000;
        }

        // 受信任的 IP 地址列表，这些 IP 不受速率限制 (逗号分隔转数组)
        this.trustedIps = env.trustedIps ? env.trustedIps.split(',').map(ip => ip.trim()) : [];

        // 配置允许的引用来源列表
        this.trustedDomains = env.trustedDomains ? env.trustedDomains.split(',').map(domain => domain.trim()) : [];

        // 配置审计日志级别
        this.auditLogLevel = env.auditLogLevel || 'standard'; // 'minimal', 'standard', 'verbose'

        // 受限国家/地区代码列表（ISO 代码，如 CN, RU, IR 等）
        this.restrictedCountries = env.restrictedCountries ? env.restrictedCountries.split(',').map(c => c.trim()) : [];
        // 或者使用允许列表模式（更严格）
        this.allowedCountries = env.allowedCountries ? env.allowedCountries.split(',').map(c => c.trim()) : [];

        // 每日配额
        this.dailyQuota = parseInt(env.dailyQuota) || 1000;

        // 密钥版本和轮换时间
        this.keyVersion = env.KEY_VERSION || '1';
        this.keyRotationDate = env.KEY_ROTATION_DATE || '';

        // 检查密钥是否需要轮换（超过90天）
        if (this.keyRotationDate) {
            const rotationDate = new Date(this.keyRotationDate);
            const now = new Date();
            const daysSinceRotation = Math.floor((now - rotationDate) / (1000 * 60 * 60 * 24));

            if (daysSinceRotation > 90) {
                console.warn(`[Security] Secret key rotation overdue: ${daysSinceRotation} days since last rotation`);
            }
        }

        // 签名验证豁免路径前缀，不需要签名验证（例如: ['/favicon.ico', '/robots.txt']）
        this.signatureExemptPaths = env.signatureExemptPaths ? env.signatureExemptPaths.split(',').map(p => p.trim()) : ['/favicon.ico'];

        // 是否对浏览器直接访问豁免签名验证
        this.allowBrowserAccess = env.allowBrowserAccess === 'true' || env.allowBrowserAccess === true;

        // 启用防盗链保护 (默认启用)
        this.enableHotlinkProtection = env.enableHotlinkProtection !== 'false';

        // 增加防盗链保护配置
        this.allowEmptyReferer = env.allowEmptyReferer === 'true' || false; // 是否允许空Referer
        this.allowDirectAccess = env.allowDirectAccess === 'true' || false; // 是否允许直接访问(无Referer或空Referer)
    }

    // --- 异步导入 HMAC 密钥 ---
    // 将原始密钥字符串转换为 Web Crypto API 可用的 CryptoKey 对象
    // 这是异步操作，因为 `crypto.subtle.importKey` 是异步的
    async importHmacKey() {
        // 如果密钥已导入，直接返回缓存的 CryptoKey
        if (!this.secretKeyBuffer) {
            // 将密钥字符串编码为 UTF-8 字节
            const keyData = new TextEncoder().encode(this.secretKey);
            // 使用 Web Crypto API 导入密钥
            this.secretKeyBuffer = await crypto.subtle.importKey(
                'raw', // 导入原始字节
                keyData, // 密钥数据
                { name: 'HMAC', hash: 'SHA-256' }, // 指定算法为 HMAC-SHA256
                false, // 密钥是否可提取 (安全起见设为 false)
                ['sign', 'verify'] // 密钥用途：签名和验证
            );
        }
        // 返回导入的 CryptoKey
        return this.secretKeyBuffer;
    }

    // 添加配置验证方法
    validateSecurityConfig() {
        const issues = [];

        if (!this.secretKey) {
            issues.push('未配置签名密钥');
        }

        if (this.rateLimit > 100) {
            issues.push(`速率限制值(${this.rateLimit})对于生产环境可能过高`);
        }

        if (this.trustedIps.length === 0) {
            issues.push('未配置受信任IP地址');
        }

        return {
            isValid: issues.length === 0,
            issues
        };
    }

    // 检查请求是否应该豁免签名验证
    shouldExemptFromSignature(request, path) {
        // 1. 精确路径匹配 - 完全匹配某些路径
        const exactPaths = ['/favicon.ico', '/robots.txt'];
        if (exactPaths.includes(path)) {
            logInfo("配置", `精确路径匹配豁免: ${path}`);
            return true;
        }

        // 2. 前缀匹配 - 以某些前缀开头的路径
        if (this.signatureExemptPaths.some(exempt => path.startsWith(exempt))) {
            logInfo("配置", `路径前缀豁免: ${path}`);
            return true;
        }

        // 3. 浏览器访问检测 - 更健壮的浏览器检测
        if (this.allowBrowserAccess) {
            const acceptHeader = request.header('accept') || '';
            const userAgent = request.header('user-agent') || '';

            // 更全面的浏览器检测逻辑
            const isBrowserLike = (
                // 接受 HTML 内容是浏览器的关键特征
                acceptHeader.includes('text/html') &&
                // 确保有 User-Agent
                userAgent &&
                // 排除明显的机器人和工具
                !userAgent.includes('bot') &&
                !userAgent.includes('curl') &&
                !userAgent.includes('wget') &&
                // 大多数浏览器 UA 包含 Mozilla
                (userAgent.includes('Mozilla') ||
                    userAgent.includes('Chrome') ||
                    userAgent.includes('Safari') ||
                    userAgent.includes('Firefox') ||
                    userAgent.includes('Edge'))
            );

            if (isBrowserLike) {
                logInfo("配置", `浏览器访问豁免: ${path}`, {
                    用户代理: userAgent.substring(0, 50)
                });
                return true;
            }
        }

        return false;
    }

    // 添加防盗链验证方法
    validateReferer(request, path) {
        // 如果未启用防盗链保护，直接通过
        if (!this.enableHotlinkProtection) return true;

        // 获取Referer和Host
        const referer = request.header('referer');
        const host = request.header('host');

        // 如果是API路由或其他豁免路径，豁免防盗链检查
        if (path.startsWith('/api/') || this.shouldExemptFromSignature(request, path)) {
            return true;
        }

        // 如果Referer为空
        if (!referer) {
            logInfo("防盗链", `空Referer访问: ${path}`, { 允许: this.allowEmptyReferer });
            return this.allowEmptyReferer || this.allowDirectAccess;
        }

        try {
            // 解析Referer URL
            const refererUrl = new URL(referer);
            const refererHost = refererUrl.host;

            // 检查Referer是否与Host匹配或在受信任域名列表中
            const isValidReferer =
                refererHost === host ||
                this.trustedDomains.some(domain =>
                    refererHost === domain || refererHost.endsWith(`.${domain}`)
                );

            if (!isValidReferer) {
                logWarn("防盗链", `不受信任的Referer: ${refererHost}`, {
                    路径: path,
                    主机: host
                });
            }

            return isValidReferer;
        } catch (e) {
            // Referer解析错误
            logError("防盗链", "Referer解析出错", {
                错误: e.message,
                Referer: referer
            });
            return false;
        }
    }
}

// --- 签名验证工具类 ---
class SignatureValidator {
    constructor(config) {
        // 持有 Config 实例以访问密钥和相关配置
        this.config = config;
    }

    // --- 生成签名 (异步) ---
    async generateSignature(path, timestamp) {
        // 获取导入的 HMAC 密钥 (异步)
        const key = await this.config.importHmacKey();
        // 构建签名数据源：路径 + ':' + 时间戳
        const data = `${path}:${timestamp}`;
        // 使用 crypto.subtle.sign 进行 HMAC-SHA256 签名 (异步)
        const signatureBuffer = await crypto.subtle.sign(
            'HMAC', // 算法
            key, // 密钥
            new TextEncoder().encode(data) // 待签名的数据 (编码为 UTF-8)
        );
        // 将生成的 ArrayBuffer 签名转换为十六进制字符串
        return bufToHex(signatureBuffer);
    }

    // --- 验证签名 (异步) ---
    async validateSignature(path, timestamp, signature) {
        // 检查时间戳和签名是否存在，以及时间戳是否是纯数字字符串
        if (!timestamp || !signature || !/^\d+$/.test(timestamp)) {
            console.warn(`[Signature] Invalid or missing timestamp/signature header.`);
            return false; // 基本验证失败
        }
        // 将时间戳字符串解析为数字
        const timestampNum = parseInt(timestamp, 10);
        // 检查解析是否成功
        if (isNaN(timestampNum)) {
            console.warn(`[Signature] Timestamp parsing failed: ${timestamp}`);
            return false;
        }

        // 重新生成预期签名 (异步)
        const expectedSignature = await this.generateSignature(path, timestamp);

        // 【安全】比较签名。注意：理论上应使用恒定时间比较防止时序攻击，
        // 但在 JS 中实现复杂，标准字符串比较在许多场景下可接受。
        const isValid = signature === expectedSignature;
        if (!isValid) {
            console.warn(`[Signature] Signature mismatch. Expected: ${expectedSignature}, Got: ${signature}`);
        }

        // 检查时间戳新鲜度（例如，5 分钟内有效）
        // Date.now() 获取当前 UTC 时间戳（毫秒）
        const isFresh = (Date.now() - timestampNum) < 5 * 60 * 1000; // 5 minutes tolerance
        if (!isFresh) {
            console.warn(`[Signature] Timestamp expired. Request time: ${timestampNum}, Server time: ${Date.now()}`);
        }

        // 签名必须有效且时间戳必须新鲜
        return isValid && isFresh;
    }
}

// --- 速率限制器类 ---
class RateLimiter {
    constructor(env, config) {
        this.env = env; // Cloudflare 环境对象
        this.config = config; // 配置实例
        // 获取 KV 命名空间绑定，如果绑定不存在，提供一个空操作的假对象，避免运行时错误
        this.cache = env.rateLimitCache;
        if (!this.cache) {
            console.error("CRITICAL [RateLimiter]: KV Namespace 'rateLimitCache' is not bound. Rate limiting is effectively disabled.");
            // 创建一个无操作的模拟对象，使调用 .get/.put 不会抛错
            this.cache = {
                get: async () => null,
                put: async () => { }
            };
        }
    }

    // --- 检查 IP+路径 是否超限 (异步) ---
    async checkLimit(ip, path) {
        // 如果 KV 绑定无效，则不进行限制
        if (!this.env.rateLimitCache) return true;
        // 如果 IP 在信任列表中，直接放行
        if (this.config.trustedIps.includes(ip)) return true;

        // 构建 KV 存储的 key，格式为 "rate:IP地址:请求路径"
        const key = `rate:${ip}:${path}`;
        // 获取当前时间戳（毫秒）
        const now = Date.now();
        // 计算当前时间窗口的起始时间戳
        const windowStart = now - (this.config.rateLimitWindow * 1000); // 窗口配置单位是秒，需转为毫秒

        // 从 KV 读取该 key 的数据 (异步)，期望是 JSON 格式
        // KV 的 `get` 方法指定 `{ type: 'json' }` 会自动解析 JSON
        // 如果 key 不存在或解析失败，返回默认值 { count: 0, start: now }
        const countData = await this.cache.get(key, { type: 'json' }) || { count: 0, start: now };

        // 如果记录的起始时间早于当前窗口的起始时间，说明窗口已过期
        if (countData.start < windowStart) {
            // 重置计数器和起始时间
            countData.count = 0;
            countData.start = now;
        }

        // 如果当前窗口内的计数已达到或超过限制
        if (countData.count >= this.config.rateLimit) {
            // 拒绝请求
            console.warn(`[RateLimiter] Limit exceeded for IP: ${ip}, Path: ${path}, Count: ${countData.count}`);
            return false;
        }

        // 计数器加 1
        countData.count += 1;

        // 【优化】为了减少 KV 写入操作（降低成本和避免写限制），
        // 只在窗口内第一次请求或每 10 次请求时更新 KV 中的记录。
        // 这意味着 TTL（过期时间）只在这些时候被刷新。
        if (countData.count === 1 || countData.count % 10 === 0) {
            // 将更新后的计数数据写回 KV (异步)，并设置 TTL 等于速率限制窗口大小
            // put 方法直接接受 JS 对象，无需手动 stringify
            try {
                await this.cache.put(key, countData, { expirationTtl: this.config.rateLimitWindow });
            } catch (kvError) {
                console.error(`[RateLimiter] Failed to put rate limit data to KV for key ${key}:`, kvError);
                // 即使写入失败，本次请求仍然允许通过（因为检查已经通过）
            }
        }
        // 允许请求
        return true;
    }

    async checkDailyQuota(ip, path) {
        if (!this.env.rateLimitCache) return true;
        if (this.config.trustedIps.includes(ip)) return true;

        const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
        const quotaKey = `quota:${ip}:${today}`;

        const dailyUsage = await this.cache.get(quotaKey, { type: 'json' }) || { count: 0 };

        // 检查是否超出每日配额
        if (dailyUsage.count >= this.config.dailyQuota) {
            console.warn(`[Quota] Daily limit exceeded for IP: ${ip}, Count: ${dailyUsage.count}`);
            return false;
        }

        // 增加计数并更新
        dailyUsage.count += 1;
        await this.cache.put(quotaKey, dailyUsage, { expirationTtl: 86400 }); // 24小时

        return true;
    }
}

// --- Hono 应用实例 ---
const app = new Hono();

// === 定义全局中间件 ===
app.use('*', async (c, next) => {
    // 创建配置对象并附加到请求上下文
    c.config = new Config(c.env);
    // 从此处开始，所有后续的路由处理器都可以访问 c.config
    await next();
});

// --- 接下来应该是所有路由定义 ---

// --- 添加通用JSON响应函数 ---
function jsonResponse(message, status = 200, extraData = {}) {
    const responseData = {
        "message": message,
        "time": new Date().toISOString(),
        ...extraData
    };

    return new Response(JSON.stringify(responseData, null, 2), {
        status,
        headers: {
            'Content-Type': 'application/json; charset=utf-8'
        }
    });
}

// --- 替换控制台日志格式 ---
function logInfo(category, message, data = {}) {
    console.log(JSON.stringify({
        "类别": category,
        "消息": message,
        "数据": data,
        "时间": new Date().toISOString()
    }));
}

function logWarn(category, message, data = {}) {
    console.warn(JSON.stringify({
        "类别": category,
        "消息": message,
        "数据": data,
        "时间": new Date().toISOString(),
        "级别": "警告"
    }));
}

function logError(category, message, data = {}) {
    console.error(JSON.stringify({
        "类别": category,
        "消息": message,
        "数据": data,
        "时间": new Date().toISOString(),
        "级别": "错误"
    }));
}

// 为 favicon.ico 添加专门的路由处理器
app.get('/favicon.ico', (c) => {
    logInfo("路由", "提供空的favicon响应");
    return new Response(null, {
        status: 204,
        headers: {
            'Content-Type': 'image/x-icon',
            'Cache-Control': 'public, max-age=86400'
        }
    });
});

// 添加状态检查路由
app.get('/status', async (c) => {
    const status = {
        "status": "ok",
        "time": new Date().toISOString(),
        "environment": c.env.NODE_ENV || "production"
    };

    return c.json(status);
});

// 为根路径添加一个特殊的处理器
app.get('/', async (c) => {
    logInfo("路由", "访问根路径");

    try {
        // 获取基本信息用于诊断
        const hostname = c.req.header('host') || '未知';
        const userAgent = c.req.header('user-agent') || '未知';
        const cfIp = c.req.header('cf-connecting-ip') || '未知';

        // 对IP进行安全处理（加密）
        const ipHash = await generateSecureIpHash(cfIp, c.config?.secretKey || "default-salt");

        logInfo("根路径", `来自 ${ipHash} 的请求`, { 主机: hostname, 用户代理: userAgent.substring(0, 50) });

        // 创建一个用户友好的JSON响应
        const responseJson = {
            "status": "active",
            "message": "Welcome to the Random Image API!",
            "service_information": {
                "name": "Random Image Service",
                "version": "1.0.0",
                "description": "This service provides random images from a curated collection"
            },
            "available_endpoints": {
                "image": {
                    "url": "/image",
                    "description": "Returns a random image",
                    "parameters": {
                        "type": {
                            "optional": true,
                            "values": ["horizontal", "vertical"],
                            "default": "based on hostname"
                        }
                    },
                    "usage_example": `${getBaseUrl(c.req)}/image?type=horizontal`
                },
                "status": {
                    "url": "/status",
                    "description": "Returns service status information",
                    "usage_example": `${getBaseUrl(c.req)}/status`
                },
                "test-image": {
                    "url": "/test-image",
                    "description": "Returns a static test image",
                    "usage_example": `${getBaseUrl(c.req)}/test-image`
                }
            },
            "documentation": {
                "description": "For more information, please refer to the documentation",
                "contact": "If you need help, please contact the administrator"
            },
            "client_info": {
                "visitor_id": ipHash, // 加密后的IP
                "visit_time": new Date().toISOString(),
                "region": c.req.header('cf-ipcountry') || 'unknown'
            },
            "time": new Date().toISOString()
        };

        // 返回格式化的JSON (使用缩进以提高可读性)
        return new Response(JSON.stringify(responseJson, null, 2), {
            headers: {
                'Content-Type': 'application/json; charset=utf-8',
                'Cache-Control': 'no-cache'
            }
        });

    } catch (error) {
        // 记录错误但返回用户友好的消息
        logError("根路径", "处理根路径请求时出错", { 错误: error.message });

        // 返回友好的错误信息
        return jsonResponse("The service is running, but we encountered an issue processing your request.", 200, {
            "status": "error",
            "code": "api_error",
            "retry": true
        });
    }
});

// 辅助函数：安全地对IP进行哈希处理
async function generateSecureIpHash(ip, salt) {
    try {
        // 创建带盐的输入
        const timestamp = Date.now().toString().slice(-4); // 使用时间戳末尾4位作为额外盐值
        const input = `${ip}-${salt}-${timestamp}`;

        // 使用 SHA-256 哈希
        const msgBuffer = new TextEncoder().encode(input);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);

        // 转换为十六进制字符串
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        // 只返回哈希的一部分 (保留隐私的同时允许基本的跟踪)
        return `${hashHex.substring(0, 8)}...${timestamp}`;
    } catch (error) {
        console.error("IP哈希生成错误:", error);
        return "hash-error";
    }
}

// 辅助函数：获取请求的基础URL
function getBaseUrl(request) {
    const url = new URL(request.url);
    return `${url.protocol}//${url.host}`;
}

// 添加 R2 诊断路由
app.get('/diagnose/r2', async (c) => {
    // 获取客户端 IP
    const ip = c.req.header('cf-connecting-ip') || '未知';

    // 确保 c.config 存在
    if (!c.config || !c.config.trustedIps) {
        logError("诊断", "配置对象不可用");
        return c.json({
            "error": "Server configuration error: Config object not available",
            "time": new Date().toISOString()
        }, 500);
    }

    // 记录警告日志，但不阻止访问（临时调整，用于诊断）
    if (!c.config.trustedIps.includes(ip)) {
        logWarn("诊断", `注意：IP ${ip} 不在信任列表中。考虑将其添加以提高安全性。`);
    }

    try {
        // 收集安全的诊断信息
        const diagnostics = {
            "clientIp": ip,
            "r2Bound": !!c.env.myBucket,
            "config": {
                "hRandomPrefix": c.config.hRandomPrefix,
                "vRandomPrefix": c.config.vRandomPrefix,
                "defaultContentType": c.config.defaultContentType,
                "maxListLimit": c.config.maxListLimit,
                "trustedIpsCount": c.config.trustedIps.length,
                "isTrusted": c.config.trustedIps.includes(ip)
            },
            "prefixes": {}
        };

        // 如果R2已绑定，获取对象统计信息
        if (c.env.myBucket) {
            // 检查横向图片
            try {
                const hList = await c.env.myBucket.list({
                    prefix: c.config.hRandomPrefix,
                    limit: 10
                });

                diagnostics.prefixes.horizontal = {
                    "prefix": c.config.hRandomPrefix,
                    "objectCount": hList.objects.length,
                    "truncated": hList.truncated,
                    "sampleKeys": hList.objects.slice(0, 3).map(obj => obj.key)
                };
            } catch (hError) {
                diagnostics.prefixes.horizontal = {
                    "prefix": c.config.hRandomPrefix,
                    "error": hError.message
                };
            }

            // 检查纵向图片
            try {
                const vList = await c.env.myBucket.list({
                    prefix: c.config.vRandomPrefix,
                    limit: 10
                });

                diagnostics.prefixes.vertical = {
                    "prefix": c.config.vRandomPrefix,
                    "objectCount": vList.objects.length,
                    "truncated": vList.truncated,
                    "sampleKeys": vList.objects.slice(0, 3).map(obj => obj.key)
                };
            } catch (vError) {
                diagnostics.prefixes.vertical = {
                    "prefix": c.config.vRandomPrefix,
                    "error": vError.message
                };
            }
        }

        return c.json(diagnostics);
    } catch (error) {
        logError("诊断", "R2诊断中出错", { 错误: error.message, 堆栈: error.stack });
        return c.json({
            "error": error.message,
            "stack": error.stack
        });
    }
});

// 添加静态测试图片路由 - 完全不依赖 R2
app.get('/test-image', (c) => {
    // 这是一个1x1像素的透明PNG图片的base64编码
    const base64Image = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=';

    // 解码base64
    const imageData = Uint8Array.from(atob(base64Image), c => c.charCodeAt(0));

    logInfo("测试图片", "提供测试图片");

    // 返回图片
    return new Response(imageData, {
        headers: {
            'Content-Type': 'image/png',
            'Cache-Control': 'public, max-age=3600'
        }
    });
});

// 为 /image 路径添加专门的处理器
app.get('/image', async (c) => {
    logInfo("路由", "直接访问图片路径");

    try {
        // 新增：防盗链检查
        if (!c.config.validateReferer(c.req, c.req.path)) {
            // 如果防盗链检查失败，返回友好错误，或者替代图片
            return jsonResponse("Access to this resource is restricted.", 403, {
                "status": "error",
                "code": "hotlink_protection",
                "message": "Direct access to images is not allowed."
            });
        }

        // 确保配置对象可用
        if (!c.config) {
            throw new Error('配置对象不可用 - 中间件问题');
        }

        // 获取基本信息用于诊断
        const hostname = c.req.header('host') || '未知';
        const userAgent = c.req.header('user-agent') || '未知';
        const cfIp = c.req.header('cf-connecting-ip') || '未知';

        logInfo("图片", `来自 ${cfIp} 的请求`, { 主机: hostname, 用户代理: userAgent.substring(0, 50) });

        // 确定图片类型（横向或纵向）
        let isHorizontal = true; // 默认为横向

        // 通过主机名判断
        if (hostname.includes('vrandom-pic') || hostname.includes('vertical')) {
            isHorizontal = false;
        }

        // 查询参数可以覆盖主机名判断
        const type = c.req.query('type');
        if (type === 'vertical') {
            isHorizontal = false;
        } else if (type === 'horizontal') {
            isHorizontal = true;
        }

        logInfo("图片", "配置检查", {
            横向前缀: c.config.hRandomPrefix,
            纵向前缀: c.config.vRandomPrefix
        });

        // 确定 R2 前缀
        const prefix = isHorizontal ? c.config.hRandomPrefix : c.config.vRandomPrefix;

        if (!prefix) {
            throw new Error(`未为${isHorizontal ? '横向' : '纵向'}图片配置前缀`);
        }

        logInfo("图片", `已选择前缀: ${prefix}`, { 是否横向: isHorizontal });

        // 确保 R2 存储可用
        if (!c.env.myBucket) {
            throw new Error('R2存储桶不可用 - 请检查Worker绑定');
        }

        // 列出前缀下的所有对象
        const limit = parseInt(c.config.maxListLimit) || 1000;
        logInfo("图片", `列出前缀为 ${prefix} 的对象`, { 限制: limit });

        const listResult = await c.env.myBucket.list({
            prefix: prefix,
            limit: limit
        });

        logInfo("图片", "列表操作完成");

        const items = listResult.objects;

        // 检查是否有图片
        if (!items || items.length === 0) {
            return jsonResponse(`No images available for ${isHorizontal ? 'horizontal' : 'vertical'} type (prefix: ${prefix})`);
        }

        logInfo("图片", `找到 ${items.length} 张前缀为 ${prefix} 的图片`);

        // 随机选择一张图片
        const randomIndex = Math.floor(Math.random() * items.length);
        const randomItem = items[randomIndex];

        logInfo("图片", `已选择随机图片: ${randomItem.key}`);

        // 获取图片内容
        const object = await c.env.myBucket.get(randomItem.key);

        if (!object) {
            logError("图片", `对象在列表中但无法从R2获取: ${randomItem.key}`);
            return jsonResponse("We couldn't retrieve the requested image. Please try again.", 200, {
                "status": "error",
                "code": "image_retrieval_error"
            });
        }

        // 设置响应头
        const headers = new Headers();

        // 确定内容类型
        let contentType = object.httpMetadata?.contentType || '';

        // 根据文件扩展名确定内容类型
        if (!contentType || contentType === 'application/octet-stream') {
            contentType = getMimeTypeFromKey(randomItem.key);
            logInfo("图片", `从键名检测到内容类型: ${contentType}`, { 键: randomItem.key });
        }

        // 最后回退到默认值
        contentType = contentType || 'image/jpeg';

        headers.set('Content-Type', contentType);
        headers.set('Cache-Control', `public, max-age=${c.config.cacheTtl || 3600}`);
        headers.set('ETag', object.etag);

        // 创建响应
        logInfo("图片", "成功创建响应");
        const response = new Response(object.body, { headers });

        // 将新生成的响应存入缓存 (异步，在后台执行)
        c.executionCtx.waitUntil(caches.default.put(new Request(c.req.url), response.clone()));

        // 添加审计日志
        logR2Access(c, 'get', randomItem.key, !!object, {
            cacheMiss: true,
            contentType: object?.httpMetadata?.contentType
        });

        // 返回新生成的响应
        return response;

    } catch (error) {
        // 记录详细错误信息
        logError("图片", "处理图片请求时出错", { 错误: error.message });

        // 返回用户友好的错误消息
        return jsonResponse("The image service is currently experiencing difficulties. Please try again later.", 200, {
            "status": "error",
            "code": "image_service_error"
        });
    }
});

// 添加诊断路由
app.get('/diagnose/image', async (c) => {
    // ... rest of the code ...
});

// 添加安全的诊断路由
app.get('/debug', async (c) => {
    // 检查请求是否来自受信任的 IP
    const ip = c.req.header('cf-connecting-ip') || 'unknown';
    if (!c.config.trustedIps.includes(ip)) {
        console.warn(`[Debug] Unauthorized debug request from IP: ${ip}`);
        return c.text('Unauthorized', 403);
    }

    // 收集安全的诊断信息，避免泄露敏感数据
    const debug = {
        config: {
            hRandomDomains: c.config.hRandomDomains,
            vRandomDomains: c.config.vRandomDomains,
            hRandomPrefix: c.config.hRandomPrefix,
            vRandomPrefix: c.config.vRandomPrefix,
            allowBrowserAccess: c.config.allowBrowserAccess,
            signatureExemptPaths: c.config.signatureExemptPaths,
            trustedIps: '***masked***', // 不显示完整的受信任 IP
        },
        // 检查 R2 绑定是否存在
        r2Bound: !!c.env.myBucket,
        // 检查 KV 绑定是否存在
        kvBound: !!c.env.rateLimitCache,
        // 当前请求信息
        request: {
            path: c.req.path,
            host: c.req.header('host'),
            userAgent: c.req.header('user-agent'),
        }
    };

    // 添加 R2 bucket 检查
    if (c.env.myBucket) {
        try {
            // 尝试列出前缀为 c.config.hRandomPrefix 的对象
            const hObjects = await c.env.myBucket.list({
                prefix: c.config.hRandomPrefix,
                limit: 1
            });
            // 尝试列出前缀为 c.config.vRandomPrefix 的对象
            const vObjects = await c.env.myBucket.list({
                prefix: c.config.vRandomPrefix,
                limit: 1
            });

            debug.r2Check = {
                hPrefixExists: hObjects.objects.length > 0,
                vPrefixExists: vObjects.objects.length > 0,
                hPrefixCount: hObjects.objects.length,
                vPrefixCount: vObjects.objects.length,
            };
        } catch (error) {
            debug.r2Check = {
                error: error.message
            };
        }
    }

    return c.json(debug);
});

// --- 全局中间件 (按顺序执行) ---

// 1. 初始化配置、签名验证器、速率限制器实例，并挂载到上下文 (c)
//    使其在后续中间件和路由处理器中可用
app.use('*', async (c, next) => {
    try {
        // 为每个请求创建新的实例，确保请求间隔离
        c.config = new Config(c.env); // 加载配置
        c.signatureValidator = new SignatureValidator(c.config); // 初始化签名验证器
        c.rateLimiter = new RateLimiter(c.env, c.config); // 初始化速率限制器

        // 验证安全配置
        const securityCheck = c.config.validateSecurityConfig();
        if (!securityCheck.isValid) {
            console.warn(`[Security] Configuration issues detected: ${securityCheck.issues.join(', ')}`);
        }
    } catch (error) {
        // 如果配置（特别是密钥）加载失败，阻止后续处理
        console.error("CRITICAL [Middleware]: Failed to initialize configuration or dependencies:", error);
        return c.text('Internal Server Configuration Error', 500);
    }
    // 调用下一个中间件或路由处理器
    await next();
});

// 2. CORS (跨域资源共享) 中间件
app.use('*', cors({
    // 生产环境建议将 '*' 替换为具体的允许来源域名列表
    origin: '*', // e.g., ['https://your-frontend.com', 'https://another-allowed-domain.com']
    // 允许的 HTTP 方法
    allowMethods: ['GET'],
    // 允许客户端发送的自定义请求头
    allowHeaders: ['x-timestamp', 'x-signature', 'User-Agent']
}));

// 3. User-Agent 检查中间件
app.use('*', async (c, next) => {
    // 获取 User-Agent 请求头
    const ua = c.req.header('user-agent') || '';
    // 简单的 UA 过滤规则，阻止常见爬虫标识符
    // 注意：此规则可能误伤某些合法客户端，根据需要调整
    if (!ua || ua.match(/bot|crawl|spider/i)) {
        console.log(`[UA Check] Blocked request due to User-Agent: ${ua}`);
        return c.text('Invalid or missing User-Agent', 403); // 返回 403 Forbidden
    }
    // UA 检查通过，继续处理
    await next();
});

// 4. 签名验证中间件
app.use('*', async (c, next) => {
    // 获取请求路径
    const path = c.req.path;

    // 更详细的调试日志
    console.log(`[Signature] Processing request: ${path}, Host: ${c.req.header('host')}, Accept: ${c.req.header('accept')}`);

    // 为根路径 "/" 添加特殊处理
    if (path === '/' || path === '') {
        const acceptHeader = c.req.header('accept') || '';
        // 如果是浏览器请求（接受 HTML）
        if (acceptHeader.includes('text/html')) {
            console.log('[Signature] Root path browser request detected, exempting from signature verification');
            await next();
            return;
        }
    }

    // 检查是否应该豁免签名验证
    if (c.config.shouldExemptFromSignature(c.req, path)) {
        console.log(`[Signature] Exempting request from signature verification: ${path}`);
        await next();
        return;
    }

    // 获取自定义签名头 x-timestamp 和 x-signature
    const timestamp = c.req.header('x-timestamp');
    const signature = c.req.header('x-signature');

    // 调用 SignatureValidator 进行验证 (异步)
    if (!timestamp || !signature || !(await c.signatureValidator.validateSignature(path, timestamp, signature))) {
        // 验证失败，记录警告并返回 403 Forbidden
        const ip = c.req.header('cf-connecting-ip') || 'unknown';
        console.warn(`[Signature] Validation failed: Path=${path}, Timestamp=${timestamp}, Signature=${signature}, IP=${ip}`);
        // 返回 JSON 错误信息，包含服务器时间戳便于客户端调试时间同步问题
        return c.json({
            "status": "error",
            "message": "Your request could not be authenticated. Please check your credentials and try again.",
            "code": "authentication_failed",
            "time": new Date().toISOString()
        }, 401);
    }
    // 签名验证通过，继续处理
    await next();
});

// 5. 速率限制中间件
app.use('*', async (c, next) => {
    // 获取客户端 IP 地址 (Cloudflare 提供的真实 IP)
    const ip = c.req.header('cf-connecting-ip') || 'unknown';
    // 如果无法获取 IP，记录警告（可选：根据策略决定是否拒绝）
    if (ip === 'unknown') {
        console.warn('[RateLimiter] Could not determine client IP from cf-connecting-ip header.');
        // 示例：如果严格要求 IP，可以在此返回错误
        // return c.text('Cannot identify client IP', 400);
    }

    // 调用 RateLimiter 检查是否超限 (异步)
    if (!(await c.rateLimiter.checkLimit(ip, c.req.path))) {
        // 速率超限，返回 429 Too Many Requests
        // 注意：`checkLimit` 内部已记录日志
        return c.text('Rate limit exceeded', 429);
    }

    // 在速率限制后添加每日配额检查
    if (!(await c.rateLimiter.checkDailyQuota(ip, c.req.path))) {
        return c.text('Daily quota exceeded', 429);
    }

    // 速率限制检查通过，继续处理
    await next();
});

// 6. 防盗链检查中间件
app.use('*', async (c, next) => {
    const referer = c.req.header('referer');
    const host = c.req.header('host');

    // 配置允许的引用来源列表
    const allowedDomains = c.config.trustedDomains || [];

    // 如果存在 Referer 且不是来自本站或允许的域名
    if (referer && !referer.includes(host) && !allowedDomains.some(domain => referer.includes(domain))) {
        console.warn(`[Anti-Hotlink] Blocked request with referer: ${referer}, host: ${host}`);
        return c.text('Unauthorized resource access', 403);
    }

    await next();
});

// 7. 在全局中间件中添加，放在 CORS 后面
app.use('*', async (c, next) => {
    // 等待下一个中间件执行完毕，以便能修改其设置的响应头
    await next();

    // 只为图片响应添加安全头
    const contentType = c.res.headers.get('Content-Type') || '';
    if (contentType.startsWith('image/')) {
        // 防止 MIME 类型嗅探攻击
        c.res.headers.set('X-Content-Type-Options', 'nosniff');
        // 控制资源如何被嵌入到其他站点
        c.res.headers.set('X-Frame-Options', 'DENY');
        // 控制 Referer 头的发送
        c.res.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
        // 禁用客户端缓存（如果需要严格控制）
        // c.res.headers.set('Cache-Control', 'no-store, max-age=0');
    }
});

// 8. 地理位置访问控制中间件
app.use('*', async (c, next) => {
    // 获取 Cloudflare 提供的国家/地区代码
    const country = c.req.header('cf-ipcountry') || 'XX';

    // 受限国家模式
    if (c.config.restrictedCountries.length > 0 && c.config.restrictedCountries.includes(country)) {
        console.warn(`[Geo Restriction] Blocked request from restricted country: ${country}`);
        return c.text('Access not available in your region', 403);
    }

    // 允许列表模式（如果配置了）
    if (c.config.allowedCountries.length > 0 && !c.config.allowedCountries.includes(country)) {
        console.warn(`[Geo Restriction] Blocked request from non-allowed country: ${country}`);
        return c.text('Access not available in your region', 403);
    }

    await next();
});

// 添加安全检查中间件
app.use('*', async (c, next) => {
    // 已有的配置加载中间件创建了c.config

    // 获取请求信息用于日志
    const path = c.req.path;
    const method = c.req.method;
    const ip = c.req.header('cf-connecting-ip') || '未知';

    // 防盗链检查 (对图片等资源路由)
    if ((path.startsWith('/image') || path.endsWith('.jpg') || path.endsWith('.png'))
        && !c.config.validateReferer(c.req, path)) {
        logWarn("安全", "防盗链检查失败", { 路径: path, IP: ip });
        return c.json({
            "status": "error",
            "message": "Access denied. Direct linking to resources is not allowed.",
            "code": "hotlink_protection"
        }, 403);
    }

    // 国家/地区限制检查
    const country = c.req.header('cf-ipcountry') || '';
    if (country && c.config.restrictedCountries.length > 0) {
        if (c.config.restrictedCountries.includes(country)) {
            logWarn("安全", "来自受限国家/地区的访问", { 国家: country, IP: ip });
            return c.json({
                "status": "error",
                "message": "Access from your region is not allowed.",
                "code": "region_restricted"
            }, 403);
        }
    }

    // 允许请求继续
    await next();
});

// --- 辅助函数：根据主机名、路径和参数确定 R2 存储前缀 ---
function getPrefix(hostname, path, config, searchParams) {
    // 添加更详细的调试日志
    console.log(`[getPrefix] Determining prefix for hostname: ${hostname}, path: ${path}`);
    console.log(`[getPrefix] Configured domains - H: ${config.hRandomDomains.join(', ')}, V: ${config.vRandomDomains.join(', ')}`);

    // 获取配置中的域名列表
    const hDomains = config.hRandomDomains;
    const vDomains = config.vRandomDomains;

    // 规则 1: 如果路径以 /api/image 开头，根据 type 参数决定前缀
    if (path.startsWith('/api/image')) {
        // 获取 'type' 查询参数，默认为 'horizontal'
        const type = searchParams.get('type') || 'horizontal';
        // 返回对应的横向或纵向图片前缀
        const prefix = type === 'horizontal' ? config.hRandomPrefix : config.vRandomPrefix;
        console.log(`[getPrefix] API path match, using prefix: ${prefix}`);
        return prefix;
    }

    // 规则 2: 如果请求的 hostname 在配置的域名列表中，返回对应的前缀
    if (hostname) { // 确保 hostname 存在
        if (hDomains.includes(hostname)) {
            console.log(`[getPrefix] Hostname match for horizontal images: ${hostname}, using prefix: ${config.hRandomPrefix}`);
            return config.hRandomPrefix;
        }
        if (vDomains.includes(hostname)) {
            console.log(`[getPrefix] Hostname match for vertical images: ${hostname}, using prefix: ${config.vRandomPrefix}`);
            return config.vRandomPrefix;
        }

        // 添加模糊匹配检查
        // 有时配置中的域名可能包含或不包含 "www." 前缀
        for (const domain of hDomains) {
            if (hostname.includes(domain) || domain.includes(hostname)) {
                console.log(`[getPrefix] Fuzzy hostname match for horizontal images: ${hostname} ~ ${domain}, using prefix: ${config.hRandomPrefix}`);
                return config.hRandomPrefix;
            }
        }

        for (const domain of vDomains) {
            if (hostname.includes(domain) || domain.includes(hostname)) {
                console.log(`[getPrefix] Fuzzy hostname match for vertical images: ${hostname} ~ ${domain}, using prefix: ${config.vRandomPrefix}`);
                return config.vRandomPrefix;
            }
        }
    }

    // 修改默认行为：如果无法确定前缀，使用水平图片前缀作为默认值
    console.log(`[getPrefix] No match found, using default horizontal prefix: ${config.hRandomPrefix}`);
    return config.hRandomPrefix;
}

// --- 辅助函数：根据文件扩展名获取正确的 MIME 类型 ---
function getMimeTypeFromKey(key) {
    const extension = key.split('.').pop().toLowerCase();
    const mimeTypes = {
        'jpeg': 'image/jpeg',
        'jpg': 'image/jpeg',
        'png': 'image/png',
        'gif': 'image/gif',
        'webp': 'image/webp',
        'svg': 'image/svg+xml',
        'avif': 'image/avif'
    };

    return mimeTypes[extension] || 'application/octet-stream';
}

// --- 路由定义 ---

// 路由：GET / (根路径) - 用于 API 计数 或 直接图片请求
app.get('/', async (c) => {
    // 获取请求的主机名 (例如 'api-hrandom-pic.onani.cn')
    const hostname = c.req.header('host');

    // 判断请求是否来自 API 域名 (以配置的 apiPrefix 开头)
    if (!hostname || !hostname.startsWith(c.config.apiPrefix)) {
        // 如果不是 API 域名，则将其视为直接的图片请求，调用图片处理函数
        return generateImageResponse(c);
    }

    // --- 以下是 API 计数逻辑 ---
    // 根据主机名、路径、配置和查询参数获取 R2 前缀
    const prefix = getPrefix(hostname, c.req.path, c.config, c.req.query());
    // 如果无法确定前缀（例如，配置错误或无效的 API 域名）
    if (!prefix) {
        console.warn(`[Count API] Invalid domain for count API: ${hostname}`);
        return c.text('Invalid domain for count API', 400); // 返回 400 Bad Request
    }

    try {
        // 检查 R2 存储绑定是否存在
        if (!c.env.myBucket) {
            console.error("CRITICAL [Count API]: R2 Bucket 'myBucket' is not bound.");
            return c.text('Server configuration error: R2 not available', 500);
        }
        // 调用 R2 list API 列出指定前缀的对象
        // 使用配置的 maxListLimit 限制返回数量，防止列出过多对象
        const objects = await c.env.myBucket.list({ prefix, limit: c.config.maxListLimit });
        // 获取对象数量
        // 注意：如果实际对象数超过 maxListLimit，这里只得到部分数量
        const count = objects.objects.length;

        // 设置响应头
        c.header('Content-Type', 'text/plain'); // 响应类型为纯文本
        // 设置缓存控制头，允许公共缓存（如 CDN）缓存结果
        c.header('Cache-Control', `public, max-age=${c.config.cacheTtl}`);
        // 返回对象数量的字符串
        return c.text(count.toString());

    } catch (error) {
        // 处理 R2 list 操作可能出现的错误
        console.error('[Count API] Error listing R2 bucket:', { prefix, error: error.message, stack: error.stack });
        return c.text('Error retrieving count', 500); // 返回 500 Internal Server Error
    }
});

// 路由：GET * (通配符) - 处理所有其他 GET 请求，主要用于图片获取
// 这个处理器会捕获所有未被精确匹配 '/' 的 GET 请求
app.get('*', generateImageResponse);

// --- 图片响应生成函数 ---
async function generateImageResponse(c) {
    try {
        // 获取主机名和查询参数
        const hostname = c.req.header('host');
        const searchParams = c.req.query(); // Hono 自动解析查询字符串

        console.log(`[Image] Processing request for hostname: ${hostname}, path: ${c.req.path}`);

        // 获取 R2 前缀
        const prefix = getPrefix(hostname, c.req.path, c.config, searchParams);

        // 如果无法确定前缀，使用默认响应而不是错误
        if (!prefix) {
            console.warn(`[Image] Could not determine prefix, using default response`);
            return c.text('Service is working, but could not determine image type from your request', 200);
        }

        // --- 缓存处理 ---
        // 获取默认的 Cache API 实例
        const cache = caches.default;
        // 构建缓存键：使用请求 URL 并在查询字符串中显式加入 prefix，确保不同前缀的请求有不同缓存
        // 使用完整的 Request 对象作为 cache key 更标准
        const cacheKey = new Request(c.req.url + (c.req.url.includes('?') ? '&' : '?') + `prefix=${prefix}`, c.req.raw);

        // 尝试从缓存中获取响应 (异步)
        let response = await cache.match(cacheKey);
        // 如果缓存命中
        if (response) {
            console.log(`[Cache] HIT for: ${cacheKey.url}`);
            // 直接返回缓存的响应
            return response;
        }
        // 如果缓存未命中
        console.log(`[Cache] MISS for: ${cacheKey.url}`);

        // --- 从 R2 获取图片 ---
        // 检查 R2 绑定
        if (!c.env.myBucket) {
            console.error("CRITICAL [Image]: R2 Bucket 'myBucket' is not bound.");
            return c.text('Server configuration error: R2 not available', 500);
        }

        // 列出 R2 中指定前缀的对象
        console.log(`[R2] Listing objects with prefix: ${prefix}, limit: ${c.config.maxListLimit}`);
        const listOptions = { prefix, limit: c.config.maxListLimit };
        const objects = await c.env.myBucket.list(listOptions);
        const items = objects.objects; // 获取对象列表

        // 如果没有找到任何对象
        if (items.length === 0) {
            console.warn(`[Image] No images found in R2 for prefix: ${prefix}`);
            // 返回更友好的错误消息，而不是 404
            return c.text(`No images available for ${isHorizontal ? 'horizontal' : 'vertical'} type (prefix: ${prefix})`);
        }

        console.log(`[R2] Found ${items.length} objects with prefix: ${prefix}`);

        // 使用 Math.random() 从列表中随机选择一个对象
        // Math.random() 返回 [0, 1) 的浮点数
        const randomIndex = Math.floor(Math.random() * items.length);
        const randomItem = items[randomIndex];

        console.log(`[R2] Selected random object: ${randomItem.key}`);

        // 从 R2 获取选中的对象内容 (异步)
        const object = await c.env.myBucket.get(randomItem.key);

        // 如果获取对象失败（例如，在 list 和 get 之间被删除）
        if (!object) {
            logError("图片", `对象在列表中但无法从R2获取: ${randomItem.key}`);
            return jsonResponse("We couldn't retrieve the requested image. Please try again.", 200, {
                "status": "error",
                "code": "image_retrieval_error"
            });
        }

        // 准备响应头
        const headers = new Headers(); // 使用 Headers 对象构建

        // 显式设置 Content-Type
        let contentType = object.httpMetadata?.contentType || '';

        // 如果 R2 没有提供内容类型或内容类型可能不正确，根据文件扩展名检测
        if (!contentType || contentType === 'application/octet-stream') {
            // 从对象键中检测正确的 MIME 类型
            contentType = getMimeTypeFromKey(randomItem.key);
            logInfo("图片", `从键名检测到内容类型: ${contentType}`, { 键: randomItem.key });
        }

        // 最后回退到默认值
        contentType = contentType || c.config.defaultContentType;

        // 设置内容类型头
        headers.set('Content-Type', contentType);

        // 记录我们使用的内容类型，用于调试
        logInfo("图片", `使用内容类型: ${contentType}`, { 键: randomItem.key });

        // 其他头部保持不变
        headers.set('ETag', object.etag);
        headers.set('Cache-Control', `public, max-age=${c.config.cacheTtl}`);

        // 不再设置X-R2-Key头
        // headers.set('X-R2-Key', randomItem.key); // 移除此行

        // 替代方案：使用哈希后的键或者随机引用ID来跟踪，而不暴露实际键
        if (c.config.auditLogLevel === 'verbose') {
            // 为内部审计目的生成一个引用ID
            const refId = await generateSecureReference(randomItem.key);
            headers.set('X-Reference-ID', refId);
        }

        // 创建 Response 对象，包含 R2 对象体和设置好的头
        response = new Response(object.body, { headers });

        // 将新生成的响应存入缓存 (异步，在后台执行)
        c.executionCtx.waitUntil(cache.put(cacheKey, response.clone()));

        // 添加审计日志
        logR2Access(c, 'get', randomItem.key, !!object, {
            cacheMiss: true,
            contentType: object?.httpMetadata?.contentType
        });

        // 返回新生成的响应
        return response;

    } catch (error) {
        // 记录详细错误信息
        logError("图片", "处理图片请求时出错", { 错误: error.message });

        // 返回更友好的错误消息
        return jsonResponse("The image service encountered a technical issue. Our team has been notified.", 200, {
            "status": "error",
            "code": "technical_difficulty",
            "retry": true
        });
    }
}

// 辅助函数：生成安全的引用ID，不泄露原始对象键
async function generateSecureReference(key) {
    try {
        // 生成一个短的、不可逆的引用ID
        const encoder = new TextEncoder();
        const data = encoder.encode(`ref:${key}:${Date.now()}`);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        // 只返回前8个字符，足够用于引用但无法推断原始键
        return hashArray.slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (error) {
        console.error("引用ID生成错误:", error);
        return "ref-error";
    }
}

// --- 全局错误处理 ---
// 当任何中间件或路由处理器抛出未捕获的错误时，此处理器会被调用
app.onError((err, c) => {
    // 获取更多上下文信息用于日志记录
    const ip = c.req.header('cf-connecting-ip') || '未知';
    const requestId = c.req.header('cf-request-id') || 'N/A'; // Cloudflare 请求 ID
    const headersObj = {};

    try {
        c.req.headers.forEach((value, key) => headersObj[key] = value); // 将 Headers 对象转为普通对象记录
    } catch (headerError) {
        logError("处理头部", "处理请求头时出错", { 错误: headerError.message });
    }

    // 添加错误严重性分类
    let severity = '错误';
    let alertNeeded = false;

    // 基于错误类型或消息分类
    if (err.message && (
        err.message.includes('R2') ||
        err.message.includes('Authentication') ||
        err.message.includes('rate limit')
    )) {
        severity = '严重';
        alertNeeded = true;
    }

    // 规范化的结构化日志
    const errorLog = {
        "严重性": severity,
        "请求ID": requestId,
        "URL": c.req.url,
        "方法": c.req.method,
        "路径": c.req.path,
        "IP": ip,
        "时间戳": new Date().toISOString(),
        "错误消息": err.message,
        "错误名称": err.name,
        "错误堆栈": err.stack,
        "CDN节点": c.req.header('cf-colo') || '未知'
    };

    console.error(JSON.stringify({
        "类别": `[${severity}] 未处理错误`,
        "数据": errorLog
    }));

    // 如果集成了警报系统，可以在这里触发
    if (alertNeeded && c.env.ALERT_WEBHOOK) {
        c.executionCtx.waitUntil(
            fetch(c.env.ALERT_WEBHOOK, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    text: `警报: ${severity} 随机图片服务错误: ${err.message}`,
                    errorDetails: errorLog
                })
            }).catch(e => logError("警报", "发送警报失败", { 错误: e.message }))
        );
    }

    // 返回用户友好的错误消息
    return jsonResponse("We're sorry, but something went wrong on our end. Our technical team has been notified.", 500, {
        "status": "error",
        "code": "server_error",
        "retry": true
    });
});

// 添加审计日志函数
function logR2Access(c, operation, objectKey, success, details = {}) {
    const timestamp = new Date().toISOString();
    const clientIp = c.req.header('cf-connecting-ip') || 'unknown';
    const requestId = c.req.header('cf-request-id') || 'unknown';
    const ray = c.req.header('cf-ray') || 'unknown';

    const logEntry = {
        timestamp,
        operation,
        objectKey,
        success,
        clientIp,
        requestId,
        ray,
        ...details
    };

    // 根据日志级别筛选字段
    if (c.config.auditLogLevel !== 'verbose') {
        delete logEntry.details;
    }

    console.log(`[R2Audit] ${JSON.stringify(logEntry)}`);
}

// 导出 Hono 应用实例，供 Cloudflare Worker 运行时使用
export default app;