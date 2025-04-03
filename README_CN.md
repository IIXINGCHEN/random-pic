# Docker 镜像代理服务 - Cloudflare Worker

这是一个基于 Cloudflare Workers 的 Docker 镜像代理服务,支持 Docker Hub、GCR、GHCR 等多种镜像仓库的代理和缓存。它提供了以下功能:

- 支持 Docker Hub（registry-1.docker.io）、GCR、GHCR 等多种镜像仓库的代理和缓存
- 静态资源处理和缓存优化
- 基于地理位置的访问控制
- 与 Cloudflare KV 存储的集成
- 优化的搜索功能
- 访问速率限制

## 功能特性

1. **多仓库支持**:
   - 支持 Docker Hub、GCR、GHCR 等主流镜像仓库的代理和缓存。
   - 根据请求的主机名自动路由到相应的仓库。

2. **静态资源优化**:
   - 处理静态资源请求,如 CSS、JavaScript、图片等。
   - 从 CDN 或应用主页获取静态资源并提供缓存。

3. **地理位置检查**:
   - 检查客户端 IP 地址是否在允许的地理范围内。
   - 仅允许中国大陆地区的访问。

4. **缓存机制**:
   - 利用 Cloudflare KV 存储缓存 Docker 镜像、认证令牌、地理位置信息和静态资源。
   - 根据缓存的有效性自动选择使用缓存或转发请求。

5. **搜索功能优化**:
   - 优化 Docker 镜像搜索功能,提高搜索结果的缓存效率。

6. **访问限制**:
   - 实现基于客户端 IP 的访问速率限制,防止过高的并发请求。

7. **安全性**:
   - 设置安全的 HTTP 响应头,如 `X-Content-Type-Options`、`X-Frame-Options`、`Content-Security-Policy` 等。
   - 检查 User-Agent 黑名单,阻止恶意访问。

## 环境变量

以下是可用的环境变量:

- `UA`: 自定义 User-Agent 黑名单 (逗号分隔)
- `WORKERS_URL`: Cloudflare Workers 部署地址
- `URL302`: 302 重定向 URL
- `URL`: 自定义重定向 URL 或 'nginx' 以使用默认页面

### `UA`

自定义 User-Agent 黑名单,用于阻止恶意访问。可以设置多个值,用逗号分隔。例如:

```
UA=netcraft,badbot,evilcrawler
```

### `WORKERS_URL`

设置 Cloudflare Workers 的部署地址。如果不设置,默认使用 `https://registry-1.axingchen.com`。

### `URL302`

设置 302 重定向的目标 URL。如果设置了这个变量,所有请求都会被重定向到该 URL。

### `URL`

自定义重定向 URL 或设置为 `'nginx'` 以使用默认页面。如果设置了 `URL302`,则该变量无效。

## 部署步骤

1. 创建所需的 KV 命名空间:

   您可以使用 Cloudflare CLI 或 Cloudflare API 来创建所需的 KV 命名空间:

   使用 Cloudflare CLI:
   ```
   cloudflare workers kv namespace create DOCKER_PROXY_KV
   cloudflare workers kv namespace create GEO_CACHE_KV
   cloudflare workers kv namespace create STATIC_RESOURCE_KV
   cloudflare workers kv namespace create AUTH_TOKEN_KV
   ```

   使用 Cloudflare API:
   ```
   # 请参考 Cloudflare API 文档进行操作
   https://api.cloudflare.com/#workers-kv-namespace-management-create-a-namespace
   ```

2. 在 Cloudflare Worker 的环境变量中绑定这些命名空间:
   ```
   cloudflare workers envvar set DOCKER_PROXY_KV <your-namespace-id>
   cloudflare workers envvar set GEO_CACHE_KV <your-namespace-id>
   cloudflare workers envvar set STATIC_RESOURCE_KV <your-namespace-id>
   cloudflare workers envvar set AUTH_TOKEN_KV <your-namespace-id>
   ```
   将 `<your-namespace-id>` 替换为对应命名空间的 ID。

3. 在 Cloudflare 控制台中创建一个新的 Worker。

4. 配置环境变量:
   - `UA`: 可选,添加自定义的 User-Agent 黑名单,多个值用逗号分隔。
   - `WORKERS_URL`: 可选,设置 Cloudflare Workers 的部署地址。
   - `URL302`: 可选,设置 302 重定向的目标 URL。
   - `URL`: 可选,设置自定义重定向 URL 或填写 `'nginx'` 来使用默认页。

5. 将 `worker.js` 文件上传到 Cloudflare Workers 的编辑器中,并保存部署。

6. 访问部署的 Worker URL,测试各项功能是否正常,包括镜像拉取、推送、认证、搜索等。

7. 使用 Cloudflare 提供的日志和分析工具,监控 Worker 的运行状态和性能,及时发现并解决潜在问题。

## 注意事项

1. **安全性**: 通过设置多种安全响应头和限制访问的地理位置,加强了服务的安全性。
2. **性能优化**: 利用 Cloudflare KV 进行高效的缓存,减少对后端 Docker 仓库的请求,提高响应速度。
3. **错误处理**: 统一的错误处理机制确保了错误信息的标准化和日志的详细记录,便于排查问题。
4. **可扩展性**: 模块化的设计使得功能的扩展和维护变得更加简便。

## 未来计划

1. **支持更多镜像仓库**: 除了 Docker Hub、GCR 和 GHCR,计划支持更多的镜像仓库,如 Quay、AWS ECR 等。
2. **增强搜索功能**: 进一步优化镜像搜索,提供更智能和高效的搜索体验。
3. **支持身份验证**: 计划增加对 Docker 镜像库的私有仓库的支持,并提供相应的身份验证机制。
4. **提供用户界面**: 计划开发一个简单的用户界面,方便用户查看服务状态和配置等信息。

## 许可证

本项目基于 MIT 许可证发布。