/**
 * 增强的安全日志模块
 * 提供结构化、分级的安全事件日志记录
 */

export class SecureLogger {
    constructor(context) {
        this.context = context || {};
        this.sensitiveFields = ['password', 'token', 'key', 'secret', 'credential'];
    }

    // 处理敏感数据，防止日志泄露
    _sanitize(data) {
        if (!data) return data;

        if (typeof data === 'object') {
            const result = Array.isArray(data) ? [] : {};

            for (const [key, value] of Object.entries(data)) {
                // 检查是否是敏感字段
                const isSensitive = this.sensitiveFields.some(field =>
                    key.toLowerCase().includes(field.toLowerCase())
                );

                if (isSensitive && typeof value === 'string') {
                    // 对敏感字段进行掩码处理
                    result[key] = '***REDACTED***';
                } else if (typeof value === 'object') {
                    // 递归处理嵌套对象
                    result[key] = this._sanitize(value);
                } else {
                    result[key] = value;
                }
            }
            return result;
        }

        return data;
    }

    // 创建日志条目
    _createEntry(level, message, data = {}) {
        const timestamp = new Date().toISOString();
        const sanitizedData = this._sanitize(data);

        return {
            timestamp,
            level,
            message,
            ...this.context,
            ...sanitizedData
        };
    }

    // 安全相关信息日志
    info(message, data = {}) {
        const entry = this._createEntry('INFO', message, data);
        console.log(`[SECURITY:INFO] ${JSON.stringify(entry)}`);
        return entry;
    }

    // 安全警告日志
    warn(message, data = {}) {
        const entry = this._createEntry('WARNING', message, data);
        console.warn(`[SECURITY:WARNING] ${JSON.stringify(entry)}`);
        return entry;
    }

    // 安全事件/错误日志
    error(message, data = {}) {
        const entry = this._createEntry('ERROR', message, data);
        console.error(`[SECURITY:ERROR] ${JSON.stringify(entry)}`);
        return entry;
    }

    // 记录安全审计事件
    audit(action, status, data = {}) {
        const entry = this._createEntry('AUDIT', `${action} - ${status}`, data);
        console.log(`[SECURITY:AUDIT] ${JSON.stringify(entry)}`);
        return entry;
    }

    // 记录可疑/异常行为
    suspicious(message, data = {}) {
        const entry = this._createEntry('SUSPICIOUS', message, data);
        console.warn(`[SECURITY:SUSPICIOUS] ${JSON.stringify(entry)}`);
        return entry;
    }
} 