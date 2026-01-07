// PM2 进程管理配置文件
// 使用方法: pm2 start ecosystem.config.js

module.exports = {
  apps: [{
    // 环境变量
    env: {
      NODE_ENV: 'production',
      // 也可以通过环境变量覆盖配置
      HOST: '127.0.0.1',
      PORT: 3000,
      AUTHORIZED_KEYS_PATH: '/Users/lianhaocheng/.ssh/authorized_keys',
    },

    name: 'ssh-key-manager',
    script: './src/server.js',
    
    // 实例数量
    instances: 1,
    
    // 执行模式
    exec_mode: 'fork',
    
    // 自动重启
    autorestart: true,
    
    // 监视文件变化（开发模式）
    watch: false,
    
    // 最大内存限制
    max_memory_restart: '500M',
    
    // 开发环境变量
    env_development: {
      NODE_ENV: 'development',
      PORT: 3000
    },
    
    // 日志配置
    error_file: './logs/pm2-error.log',
    out_file: './logs/pm2-output.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    
    // 合并日志
    merge_logs: true,
    
    // 日志轮转
    log_type: 'json',
    
    // 最小运行时间（避免频繁重启）
    min_uptime: '10s',
    
    // 异常重启延迟
    restart_delay: 4000,
    
    // 最大重启次数
    max_restarts: 10,
    
    // 监听延迟
    listen_timeout: 3000,
    
    // 关闭超时
    kill_timeout: 5000
  }]
};
