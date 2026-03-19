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

    sshUser: process.env.SSH_USER || 'jumpuser'
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

  // SSH Tunnel 端口分配配置
  tunnel: {
    // 可分配端口最小值（含）
    portMin: parseInt(process.env.TUNNEL_MIN_PORT || '6000', 10),
    // 可分配端口最大值（含）
    portMax: parseInt(process.env.TUNNEL_MAX_PORT || '6100', 10),
    // 轮询检测活跃隧道的间隔（毫秒）
    pollIntervalMs: parseInt(process.env.TUNNEL_POLL_INTERVAL_MS || '10000', 10),
  },

  // NAT 穿透中继配置
  relay: {
    // 是否启用 TCP 中继（纯 Node.js 实现，不依赖 SSH）
    tcpEnabled: process.env.RELAY_TCP_ENABLED !== 'false',
    // 是否启用 UDP 中继
    udpEnabled: process.env.RELAY_UDP_ENABLED === 'true',
    // TCP/UDP 中继端口范围（与 SSH 隧道共用同一资源池时，需避免重叠）
    portMin: parseInt(process.env.RELAY_PORT_MIN || process.env.TUNNEL_MIN_PORT || '6000', 10),
    portMax: parseInt(process.env.RELAY_PORT_MAX || process.env.TUNNEL_MAX_PORT || '6100', 10),
    // 中继客户端心跳超时（毫秒），超时后视为离线
    clientTimeoutMs: parseInt(process.env.RELAY_CLIENT_TIMEOUT_MS || '30000', 10),
  },

  // 超管配置
  admin: {
    // 超管访问令牌，从环境变量读取（未设置则禁用超管入口）
    token: process.env.ADMIN_TOKEN || '',
  },

  // 日志配置
  logging: {
    // 是否启用详细日志
    verbose: process.env.NODE_ENV !== 'production',
  },
};