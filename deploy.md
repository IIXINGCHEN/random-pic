# Random Pic Worker 生产环境部署文档

本文档指导你如何将 `random-pic-worker` Cloudflare Worker 部署到生产环境。

## 目录

1.  [先决条件](#先决条件)
2.  [配置步骤](#配置步骤)
    * [创建 Cloudflare 资源](#创建-cloudflare-资源)
    * [配置 `wrangler.toml`](#配置-wranglertoml)
    * [生成和配置签名密钥 (Secret)](#生成和配置签名密钥-secret)
3.  [部署步骤](#部署步骤)
4.  [部署后步骤](#部署后步骤)
    * [配置 DNS](#配置-dns)
    * [测试验证](#测试验证)
    * [监控](#监控)
5.  [常见问题排查](#常见问题排查)
6.  [密钥管理和轮换](#密钥管理和轮换)
7.  [防盗链保护配置](#防盗链保护配置)

## 先决条件

在开始部署之前，请确保你已满足以下条件：

1.  拥有一个 Cloudflare 账户。
2.  安装了 Node.js 和 npm (或 yarn)。
3.  安装了最新版本的 Cloudflare Wrangler CLI (`npm install -g wrangler`)。
4.  通过 `wrangler login` 命令登录到你的 Cloudflare 账户。
5.  获取了 `random-pic-worker` 的项目代码。

## 配置步骤

在执行部署命令之前，必须完成以下配置：

### 创建 Cloudflare 资源

你需要在 Cloudflare Dashboard 中为生产环境创建以下资源：

1.  **R2 Bucket**:
    * 访问 Cloudflare Dashboard -> R2 -> 创建存储桶 (Create bucket)。
    * 设置一个唯一的存储桶名称 (例如 `my-prod-random-pics`)。
    * **记下这个存储桶名称**，稍后需要填入 `wrangler.toml`。
    * 将你的图片文件上传到此 R2 Bucket 中，并确保对象键符合 `wrangler.toml` 中配置的 `hRandomPrefix` 和 `vRandomPrefix` 规则 (例如 `ri/h/image1.jpg`, `ri/v/image2.png`)。
2.  **KV Namespace**:
    * 访问 Cloudflare Dashboard -> Workers & Pages -> KV -> 创建命名空间 (Create a namespace)。
    * 设置一个名称 (例如 `prod-rate-limit-cache`)。
    * **记下这个 KV Namespace 的 ID** (不是名称)，稍后需要填入 `wrangler.toml`。

### 配置 `wrangler.toml`

打开项目根目录下的 `wrangler.toml` 文件，重点关注 `[env.production]` 部分：

1.  **`[env.production.vars]`**:
    * 将 `hRandomDomains` 和 `vRandomDomains` 的值替换为你在生产环境中实际使用的域名 (例如 `"hrandom.yourdomain.com, api-hrandom.yourdomain.com"`)。
    * 根据需要调整 `hRandomPrefix`, `vRandomPrefix`, `defaultContentType`, `apiPrefix`。
    * 确认 `rateLimit`, `rateLimitWindow`, `cacheTtl`, `maxListLimit` 的值符合生产环境需求。
    * 将 `trustedIps` 替换为实际需要排除速率限制的 IP 地址列表，或者留空 `""` 如果没有。
2.  **`[[env.production.kv_namespaces]]`**:
    * 找到 `binding = "rateLimitCache"` 的条目。
    * 将其 `id` 的值替换为你**创建的生产环境 KV Namespace 的 ID**。
3.  **`[[env.production.r2_buckets]]`**:
    * 找到 `binding = "myBucket"` 的条目。
    * 将其 `bucket_name` 的值替换为你**创建的生产环境 R2 Bucket 的名称**。

**请仔细检查所有替换的值是否正确无误。**

### 生成和配置签名密钥 (Secret)

这是**极其重要**的安全步骤，用于保护你的 API 不被未授权访问。我们提供了一个专门的密钥生成工具，确保使用加密安全的强密钥。

#### 1. 生成密钥

1. 在项目根目录下，运行以下命令生成一个强密钥并测试其有效性：

   ```bash
   # 生成默认强度密钥(64字节/512位)并测试
   node script/key-generator.js --test
   ```

2. 脚本会自动创建密钥存储目录并生成两个文件：
   - 存储当前密钥的文件
   - 存储密钥历史记录的文件

3. 脚本会显示密钥信息并自动测试签名功能：
   - 十六进制密钥（推荐用于 Cloudflare）
   - Base64 格式密钥（备用格式）
   - 密钥强度分析

#### 2. 设置 Cloudflare Secrets

脚本会生成部署命令。复制并执行这些命令将密钥配置到 Cloudflare：

```bash
# 设置主签名密钥（复制脚本输出中的实际命令）
wrangler secret put API_SIGNING_KEY --env production
# 命令会提示你输入密钥值，粘贴脚本生成的十六进制密钥

# 记录密钥版本
wrangler secret put VERSION_ID --env production
# 输入版本号，例如: 1

# 记录密钥创建/轮换日期
wrangler secret put ROTATION_DATE --env production
# 输入今天的日期，格式为 YYYY-MM-DD
```

**重要提示：**
- 妥善保管生成的密钥信息，密钥目录已配置为仅所有者可读写。
- 永远不要在代码、配置文件或版本控制系统中存储这些密钥。
- 定期（建议每90天）轮换密钥，详见下方的[密钥管理和轮换](#密钥管理和轮换)部分。

## 部署步骤

完成所有配置后，执行以下步骤进行部署：

1.  在终端中，确保你位于项目根目录下。
2.  如果项目有依赖 (如此处使用了 Hono)，运行 `npm install` (或 `yarn install`) 来安装依赖。
3.  执行部署命令：

    ```bash
    wrangler deploy --env production
    ```

4.  Wrangler 将会编译、上传 Worker 代码，并将其部署到 Cloudflare 的边缘网络。留意终端输出，确认部署成功。部署成功后会显示 Worker 的访问 URL (例如 `random-pic-worker-prod.youraccount.workers.dev`)。

## 部署后步骤

部署成功后，还需要进行以下操作：

### 配置 DNS

为了让用户通过你的自定义域名 (例如 `hrandom.yourdomain.com`) 访问 Worker，你需要配置 DNS：

1.  登录到你的 DNS 提供商 (可能是 Cloudflare，也可能是其他域名注册商)。
2.  为 `wrangler.toml` 中 `hRandomDomains` 和 `vRandomDomains` 列出的**每一个域名** (包括 `api-` 前缀的域名) 创建 `CNAME` 记录。
3.  将这些 `CNAME` 记录指向 **Wrangler 部署成功后显示的 Worker URL** (例如 `random-pic-worker-prod.youraccount.workers.dev`)。

    **示例 CNAME 记录:**
    * `hrandom.yourdomain.com` -> CNAME -> `random-pic-worker-prod.youraccount.workers.dev`
    * `api-hrandom.yourdomain.com` -> CNAME -> `random-pic-worker-prod.youraccount.workers.dev`
    * `vrandom.yourdomain.com` -> CNAME -> `random-pic-worker-prod.youraccount.workers.dev`
    * `api-vrandom.yourdomain.com` -> CNAME -> `random-pic-worker-prod.youraccount.workers.dev`

4.  等待 DNS 记录生效 (可能需要几分钟到几小时)。

### 测试验证

在 DNS 生效后，彻底测试 Worker 的所有功能：

1.  使用配置的域名访问图片 (例如 `https://hrandom.yourdomain.com/`)，确认能随机返回正确的横向图片。
2.  使用配置的纵向域名访问图片 (例如 `https://vrandom.yourdomain.com/`)，确认能随机返回正确的纵向图片。
3.  使用 API 域名访问根路径 (例如 `https://api-hrandom.yourdomain.com/`)，确认能返回正确的图片数量。
4.  使用工具 (如 Postman 或 curl) 测试 API 签名验证是否按预期工作（提供正确和错误的签名/时间戳）。
5.  测试速率限制是否生效（从未信任的 IP 发送超过限制的请求）。
6.  检查浏览器缓存 (`Cache-Control`, `ETag`) 是否按预期工作。

### 监控

部署上线后，持续监控 Worker 的运行状况：

1.  **Cloudflare Dashboard**:
    * 查看 Workers & Pages -> Overview / Analytics：监控请求数、成功率、错误率、CPU 时间、内存使用等。
    * 查看 Workers & Pages -> Logs：实时查看 Worker 的 `console.log`/`console.error` 输出，排查问题。
2.  **Logpush (推荐)**:
    * 配置 Logpush 将 Worker 日志推送到你选择的分析平台 (如 Datadog, Splunk, S3 等) 进行更深入的分析和告警。

## 常见问题排查

* **Worker 返回错误 (500 Internal Server Error)**: 检查 Cloudflare Dashboard 的 Worker 日志，查找具体的 `console.error` 输出。常见原因包括：
    * 代码错误 (特别是与 Web Crypto API、KV、R2 交互部分)。
    * `wrangler.toml` 中的绑定名称 (`binding`) 与代码 (`c.env.<binding>`) 不匹配。
    * KV/R2 资源不存在或配置错误。
    * 签名密钥未设置或名称不匹配。
* **签名验证失败 (403 Forbidden)**:
    * 确认客户端生成签名使用的密钥与 Cloudflare Secret 中设置的完全一致。
    * 确认客户端生成签名使用的数据 (`path:timestamp`) 与服务器端验证时一致。
    * 检查客户端和服务器的时间戳是否同步（允许 5 分钟误差）。
    * 检查请求头 `x-timestamp`, `x-signature` 是否正确发送。
* **速率限制不生效或误判**:
    * 确认 `wrangler.toml` 中 `rateLimitCache` 的 `id` 指向正确的 KV Namespace。
    * 检查 `trustedIps` 配置是否正确。
    * 检查客户端 IP 是否被 Cloudflare 正确识别 (`cf-connecting-ip` 头)。
* **自定义域名无法访问**:
    * 检查 DNS `CNAME` 记录是否正确配置并已生效。
    * 确认 Worker 在 Cloudflare Dashboard 中已正确部署并处于活动状态。
    * 检查 Cloudflare 的 SSL/TLS 设置是否适用于该子域名。

## 密钥管理和轮换

为了保持安全性，应定期轮换签名密钥。推荐每 90 天进行一次密钥轮换。

### 执行密钥轮换

1. 使用密钥生成脚本生成新密钥，并保留前一个密钥用于平滑过渡：

   ```bash
   # 生成新密钥并保留前一个密钥
   node script/key-generator.js --rotate --test
   ```

2. 执行脚本提供的 Wrangler 命令来更新密钥：

   ```bash
   # 设置新的主签名密钥
   wrangler secret put API_SIGNING_KEY --env production
   # 粘贴脚本生成的新密钥

   # 更新密钥版本（递增之前的版本号）
   wrangler secret put VERSION_ID --env production

   # 更新密钥轮换日期
   wrangler secret put ROTATION_DATE --env production
   # 输入当前日期

   # 设置前一个密钥（用于过渡期验证）
   wrangler secret put API_SIGNING_KEY_PREVIOUS --env production
   # 粘贴脚本显示的前一个密钥
   ```

3. 重新部署 Worker 以使用新密钥：

   ```bash
   wrangler deploy --env production
   ```

4. 更新所有客户端应用使用新密钥，但给予一定的过渡期（Worker 会同时接受新旧密钥签名）。

5. 过渡期结束后（建议1-2周），可以移除旧密钥：

   ```bash
   # 移除前一个密钥
   wrangler secret delete API_SIGNING_KEY_PREVIOUS --env production
   ```

祝你部署顺利！

## 防盗链保护配置

为防止外部网站直接链接您的图片资源导致的带宽盗用和不当使用，服务内置了防盗链保护机制。

### 基本配置项

在`wrangler.toml`中，以下配置项控制防盗链行为：

```toml
# 启用防盗链保护 (默认为true)
enableHotlinkProtection = "true"

# 允许空Referer的请求 (默认为false)
allowEmptyReferer = "false"

# 允许直接访问 (默认为false)
allowDirectAccess = "false"

# 受信任的域名列表，多个域名用逗号分隔
trustedDomains = "hrandom-pic.imixc.top,api-hrandom-pic.imixc.top,vrandom-pic.imixc.top,api-vrandom-pic.imixc.top"
```

### 配置说明

- **enableHotlinkProtection**: 总开关，设置为"false"会完全禁用防盗链检查
- **allowEmptyReferer**: 控制是否允许没有Referer头的请求（一些浏览器因隐私设置可能不发送Referer）
- **allowDirectAccess**: 控制是否允许直接访问（如用户直接在浏览器地址栏输入图片URL）
- **trustedDomains**: 定义允许引用您图片的域名列表，**必须包含您配置的所有服务域名**

### 实施细节

1. **工作原理**：
   - 服务检查HTTP请求的`Referer`头
   - 只有来自受信任域名的请求才能访问图片
   - 非信任来源的请求会收到HTTP 403错误

2. **安全增强**：
   - 防盗链机制与签名验证共同工作
   - 所有图片URL不暴露实际存储路径
   - 响应不包含可追溯到原始存储的敏感头部信息

3. **配置建议**：
   - 生产环境推荐启用防盗链保护
   - 如果您的应用需要支持从移动应用或无Referer环境访问图片，请启用`allowEmptyReferer`
   - 确保`trustedDomains`包含所有合法使用您图片的域名

### 调试防盗链问题

如果合法请求被错误地阻止：

1. 检查请求的`Referer`头是否正确发送
2. 确认该域名是否已添加到`trustedDomains`
3. 临时设置`allowEmptyReferer = "true"`进行测试
4. 查看Worker日志中的防盗链相关警告

注意：防盗链保护主要针对图片资源路由（如`/image`），API路由不受影响。