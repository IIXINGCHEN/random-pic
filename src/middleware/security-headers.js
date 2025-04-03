/**
 * 增强的安全响应头中间件
 * 为所有响应添加全面的安全响应头
 */

export default function securityHeaders() {
    return async (c, next) => {
        // 等待下一个中间件
        await next();

        // 设置基本安全响应头
        c.res.headers.set('X-Content-Type-Options', 'nosniff');
        c.res.headers.set('X-Frame-Options', 'DENY');
        c.res.headers.set('X-XSS-Protection', '1; mode=block');
        c.res.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');

        // 设置内容安全策略
        // 注意：CSP应按需定制
        c.res.headers.set('Content-Security-Policy', "default-src 'none'; img-src 'self'");

        // 设置权限策略，限制潜在的危险功能
        c.res.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

        // 对图片响应设置Cache-Control
        const contentType = c.res.headers.get('Content-Type') || '';
        if (contentType.startsWith('image/')) {
            // 配置公共缓存时间，但要求验证
            c.res.headers.set('Cache-Control', `public, max-age=${c.config.cacheTtl}, must-revalidate`);
        }
    };
} 