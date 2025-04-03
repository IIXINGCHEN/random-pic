/**
 * 安全配置验证器
 * 验证并提供关于应用安全配置的反馈
 */

export class SecurityConfigValidator {
    constructor(config) {
        this.config = config;
        this.issues = [];
        this.warnings = [];
    }

    // 验证基本安全配置
    validateBasicSecurity() {
        // 验证密钥配置
        if (!this.config.secretKey) {
            this.issues.push('未配置签名密钥');
        }

        // 验证速率限制
        if (this.config.rateLimit > 100) {
            this.warnings.push(`速率限制值(${this.config.rateLimit})对于生产环境可能过高`);
        }

        // 验证缓存时间
        if (this.config.cacheTtl < 60) {
            this.warnings.push(`缓存TTL(${this.config.cacheTtl}秒)可能过短，影响性能`);
        }

        // 验证受信任IP设置
        if (this.config.trustedIps.length === 0) {
            this.warnings.push('未配置受信任IP地址，这会影响管理功能');
        }

        return this;
    }

    // 验证防盗链配置
    validateHotlinkProtection() {
        if (!this.config.enableHotlinkProtection) {
            this.warnings.push('防盗链保护已禁用，可能导致资源被滥用');
        }

        if (this.config.enableHotlinkProtection) {
            if (this.config.allowEmptyReferer) {
                this.warnings.push('允许空Referer请求，降低了防盗链保护效果');
            }

            if (this.config.allowDirectAccess) {
                this.warnings.push('允许直接访问，降低了防盗链保护效果');
            }

            if (this.config.trustedDomains.length === 0) {
                this.issues.push('防盗链保护已启用，但未配置受信任域名');
            }
        }

        return this;
    }

    // 获取验证结果
    getResults() {
        return {
            isValid: this.issues.length === 0,
            hasWarnings: this.warnings.length > 0,
            issues: this.issues,
            warnings: this.warnings
        };
    }

    // 静态方法：执行完整验证
    static validate(config) {
        return new SecurityConfigValidator(config)
            .validateBasicSecurity()
            .validateHotlinkProtection()
            .getResults();
    }
} 