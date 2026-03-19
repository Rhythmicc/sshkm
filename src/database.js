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

  // === 数据迁移：为 ssh_keys 增加 tunnel_port 列（兼容已有数据库）===
  db.run(`ALTER TABLE ssh_keys ADD COLUMN tunnel_port INTEGER NULL`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('迁移 tunnel_port 列失败:', err.message);
    }
  });
  // tunnel_port 唯一索引（允许 NULL 重复，实际由应用层保证非空时唯一）
  db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_tunnel_port ON ssh_keys(tunnel_port)
    WHERE tunnel_port IS NOT NULL`);

  // === 数据迁移：为 users 增加 username 列（兼容已有数据库）===
  db.run(`ALTER TABLE users ADD COLUMN username TEXT NULL`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('迁移 username 列失败:', err.message);
    }
  });

  // === 数据迁移：为 ssh_keys 增加 is_public 列（兼容已有数据库）===
  db.run(`ALTER TABLE ssh_keys ADD COLUMN is_public INTEGER DEFAULT 0`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('迁移 is_public 列失败:', err.message);
    }
  });
});

module.exports = db;
