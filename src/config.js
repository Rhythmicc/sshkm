module.exports = {
  // 服务器配置
  server: {
    // 服务监听端口
    port: process.env.PORT,
    host: process.env.HOST,
  },

  // SSH 公钥配置
  ssh: {
    // authorized_keys 文件路径
    // 默认：/home/jumpuser/.ssh/authorized_keys
    authorizedKeysPath: process.env.AUTHORIZED_KEYS_PATH,

    // authorized_keys 文件权限（八进制）
    authorizedKeysMode: 0o600,

    // .ssh 目录权限（八进制）
    sshDirMode: 0o700,
  },

  // 安全配置
  security: {
    // 速率限制：时间窗口（毫秒）
    rateLimitWindowMs: 15 * 60 * 1000, // 15 分钟

    // 速率限制：最大请求数
    rateLimitMaxRequests: 100,

    // 2FA TOTP 时间窗口（允许的时间偏差）
    totpWindow: 2,
  },

  // 数据库配置
  database: {
    // SQLite 数据库文件路径
    path: './database.db',
  },

  // 日志配置
  logging: {
    // 是否启用详细日志
    verbose: process.env.NODE_ENV !== 'production',
  },
};