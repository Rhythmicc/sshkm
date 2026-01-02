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

  // 创建索引
  db.run(`CREATE INDEX IF NOT EXISTS idx_fingerprint ON users(fingerprint)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_user_id ON ssh_keys(user_id)`);
});

module.exports = db;
