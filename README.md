# Random Picture Service

## 简介
基于Cloudflare Workers的随机图片服务，可以提供水平和垂直两种布局的随机图片。服务支持多域名配置、签名验证、速率限制和CDN缓存优化，适合需要随机图片展示的网站和应用。

## 特性
- **多域名支持**: 可分别配置水平和垂直图片的域名
- **安全防护**: 签名验证机制防止滥用
- **速率限制**: 动态调整的请求限制，防止资源耗尽
- **缓存优化**: 自动设置适当的缓存头，优化CDN和浏览器缓存
- **计数API**: 支持获取图片库中的图片数量

## 部署方法

### 前提条件
- Cloudflare账户
- 已配置的R2存储桶，用于存储图片
- Node.js和npm安装环境

### 安装步骤
1. 克隆仓库到本地:
```bash
git clone <仓库地址>
cd <项目文件夹>
```

2. 安装依赖:
```bash
npm install
```

3. 配置`wrangler.toml`:
   - 修改`hRandomDomains`和`vRandomDomains`为你的域名
   - 设置签名验证密钥为一个安全的随机字符串
   - 配置R2存储桶和KV命名空间信息

4. 本地开发和测试:
```bash
npm run dev
```

5. 部署到Cloudflare Workers:
```bash
npm run deploy
```

## 图片存储格式

在R2存储桶中，图片应按以下格式组织:
- 水平图片存储在`ri/h/`前缀下
- 垂直图片存储在`ri/v/`前缀下

前缀可在`wrangler.toml`中自定义。

## 使用方法

### 获取随机图片
直接访问配置的域名即可获取一张随机图片:
```
https://hrandom-pic.example.com  # 获取水平随机图片
https://vrandom-pic.example.com  # 获取垂直随机图片
```

### 获取图片计数
使用API前缀访问域名可获取图片数量:
```
https://api-hrandom-pic.example.com  # 获取水平图片数量
https://api-vrandom-pic.example.com  # 获取垂直图片数量
```

### 客户端签名生成
为防止滥用，所有请求需要携带有效签名:

```javascript
// 客户端签名生成示例
const crypto = require('crypto');
const path = '/'; // 请求路径
const timestamp = Date.now(); // 当前时间戳
const apiSigningKey = 'your-secure-signing-key'; // 与服务端配置的签名密钥一致
const data = `${path}:${timestamp}`;
const signature = crypto.createHmac('sha256', apiSigningKey).update(data).digest('hex');

// 请求时需要携带以下头部
// x-timestamp: timestamp
// x-signature: signature
```

## 配置说明

在`wrangler.toml`中可配置以下选项:

| 配置项 | 说明 |
|--------|------|
| hRandomDomains | 水平随机图片域名列表 |
| vRandomDomains | 垂直随机图片域名列表 |
| hRandomPrefix | 水平图片在R2中的前缀 |
| vRandomPrefix | 垂直图片在R2中的前缀 |
| defaultContentType | 默认内容类型 |
| apiPrefix | API请求前缀 |
| rateLimit | 每分钟速率限制 |
| rateLimitWindow | 速率限制窗口（秒） |
| cacheTtl | 缓存存活时间（秒） |
| signingKey | 用于API签名验证的密钥 |
| maxListLimit | 最大列表返回数 |
| trustedIps | 白名单IP列表 |
| dynamicRateThreshold | 动态速率调整阈值 |

## 安全注意事项
- 务必修改默认的签名密钥为一个强随机值
- 根据需要调整速率限制参数
- 考虑为敏感操作设置IP白名单

## 安全配置说明

本服务默认启用了防盗链保护机制，防止未授权网站直接链接和访问图片资源。以下配置已在`wrangler.toml`中预设：

```toml
# 防盗链保护配置
enableHotlinkProtection = "true"  # 启用防盗链保护
allowEmptyReferer = "false"       # 不允许空Referer请求
allowDirectAccess = "false"       # 不允许直接访问
trustedDomains = "域名1,域名2,..." # 允许的域名列表
```

**重要提示**：部署前，请确保`trustedDomains`包含您所有的服务域名，否则可能导致图片无法正常显示。详细配置说明请参阅`deploy.md`文档中的"防盗链保护配置"部分。

## 许可协议
[MIT](LICENSE) 

## 贡献者
[iixingchen](https://github.com/iixingchen)

## 鸣谢
感谢所有为该项目做出贡献的开发者。

## 免责声明
本项目仅提供图片服务，不承担任何法律责任。使用者应自行承担使用风险。

## 联系方式
如有任何问题或建议，请通过以下方式联系：  



