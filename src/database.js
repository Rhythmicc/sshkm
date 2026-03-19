const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const config = require('./config');

const dbPath = path.resolve(__dirname, '..', config.database.path);
const db = new sqlite3.Database(dbPath);

// 初始化数据库
db.serialize(() => {
  // 全局 2FA 密钥表（只有一条记录，所有用户共享）
  db.run(`
    CREATE TABLE IF NOT EXISTS global_totp (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      totp_secret TEXT NOT NULL,
      qr_token TEXT UNIQUE NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // 用户表（使用浏览器指纹作为标识）
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      fingerprint TEXT UNIQUE NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // SSH 公钥表
  db.run(`
    CREATE TABLE IF NOT EXISTS ssh_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      fingerprint TEXT NOT NULL,
      public_key TEXT NOT NULL,
      comment TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // 指纹映射表（多个指纹指向同一个用户）
  db.run(`
    CREATE TABLE IF NOT EXISTS fingerprint_mapping (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      fingerprint TEXT UNIQUE NOT NULL,
      is_primary INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // 创建索引
  db.run(`CREATE INDEX IF NOT EXISTS idx_fingerprint ON users(fingerprint)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_user_id ON ssh_keys(user_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_fingerprint_mapping ON fingerprint_mapping(fingerprint)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_fingerprint_mapping_user ON fingerprint_mapping(user_id)`);

  // === NAT 穿透：中继客户端表（非 SSH 的 TCP/UDP 代理客户端）===
  db.run(`
    CREATE TABLE IF NOT EXISTS relay_clients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      name TEXT,
      token TEXT UNIQUE NOT NULL,
      last_seen DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // === NAT 穿透：统一端口转发规则表（SSH/TCP/UDP 共用端口资源池）===
  db.run(`
    CREATE TABLE IF NOT EXISTS relay_rules (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      relay_client_id INTEGER,
      protocol TEXT NOT NULL DEFAULT 'ssh',
      listen_port INTEGER NOT NULL UNIQUE,
      target_host TEXT DEFAULT 'localhost',
      target_port INTEGER,
      name TEXT,
      enabled INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (relay_client_id) REFERENCES relay_clients(id) ON DELETE SET NULL
    )
  `);

  db.run(`CREATE INDEX IF NOT EXISTS idx_relay_rules_user ON relay_rules(user_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_relay_clients_user ON relay_clients(user_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_relay_clients_token ON relay_clients(token)`);

  // === 数据迁移：为 ssh_keys 增加 tunnel_port 列（兼容已有数据库）===
  db.run(`ALTER TABLE ssh_keys ADD COLUMN tunnel_port INTEGER NULL`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('迁移 tunnel_port 列失败:', err.message);
    }
  });
  // === 数据迁移：为 users 增加 display_name 列（超管可为用户设置显示名）===
  db.run(`ALTER TABLE users ADD COLUMN display_name TEXT NULL`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('迁移 display_name 列失败:', err.message);
    }
  });
  // tunnel_port 唯一索引（允许 NULL 重复，实际由应用层保证非空时唯一）
  db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_tunnel_port ON ssh_keys(tunnel_port)
    WHERE tunnel_port IS NOT NULL`);
});

module.exports = db;
