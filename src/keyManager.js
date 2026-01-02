const fs = require('fs');
const path = require('path');
const config = require('./config');
const db = require('./database');

const AUTHORIZED_KEYS_PATH = config.ssh.authorizedKeysPath;

/**
 * 同步所有公钥到 authorized_keys 文件
 */
function syncAuthorizedKeys() {
  return new Promise((resolve, reject) => {
    // 获取所有公钥
    db.all('SELECT public_key, comment FROM ssh_keys ORDER BY id', [], (err, rows) => {
      if (err) {
        console.error('数据库查询错误:', err);
        return reject(err);
      }

      try {
        // 确保目录存在
        const sshDir = path.dirname(AUTHORIZED_KEYS_PATH);
        if (!fs.existsSync(sshDir)) {
          fs.mkdirSync(sshDir, { recursive: true, mode: config.ssh.sshDirMode });
        }

        // 生成文件内容
        const content = rows.map(row => {
          const comment = row.comment ? ` ${row.comment}` : '';
          return `${row.public_key}${comment}`;
        }).join('\n');

        // 写入文件
        fs.writeFileSync(AUTHORIZED_KEYS_PATH, content + '\n', { mode: config.ssh.authorizedKeysMode });
        console.log(`已同步 ${rows.length} 个公钥到 ${AUTHORIZED_KEYS_PATH}`);
        resolve();
      } catch (error) {
        console.error('文件写入错误:', error);
        reject(error);
      }
    });
  });
}

/**
 * 验证公钥格式
 */
function validatePublicKey(publicKey) {
  // 基本格式验证：ssh-rsa/ssh-ed25519/ecdsa-sha2-nistp256 等
  const keyPattern = /^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp\d+|ssh-dss)\s+[A-Za-z0-9+\/=]+(\s+.*)?$/;
  return keyPattern.test(publicKey.trim());
}

/**
 * 添加公钥
 */
function addKey(userId, fingerprint, publicKey, comment) {
  return new Promise((resolve, reject) => {
    const trimmedKey = publicKey.trim();
    
    if (!validatePublicKey(trimmedKey)) {
      return reject(new Error('无效的公钥格式'));
    }

    // 检查公钥是否已存在
    db.get(
      'SELECT id FROM ssh_keys WHERE public_key = ?',
      [trimmedKey],
      (err, row) => {
        if (err) return reject(err);
        if (row) return reject(new Error('该公钥已存在'));

        // 插入新公钥
        db.run(
          'INSERT INTO ssh_keys (user_id, fingerprint, public_key, comment) VALUES (?, ?, ?, ?)',
          [userId, fingerprint, trimmedKey, comment],
          function(err) {
            if (err) return reject(err);
            
            // 同步到文件
            syncAuthorizedKeys()
              .then(() => resolve({ id: this.lastID }))
              .catch(reject);
          }
        );
      }
    );
  });
}

/**
 * 删除公钥（只能删除自己添加的）
 */
function deleteKey(keyId, fingerprint) {
  return new Promise((resolve, reject) => {
    // 先验证这个公钥是否属于该用户
    db.get(
      `SELECT sk.id FROM ssh_keys sk 
       JOIN users u ON sk.user_id = u.id 
       WHERE sk.id = ? AND u.fingerprint = ?`,
      [keyId, fingerprint],
      (err, row) => {
        if (err) return reject(err);
        if (!row) return reject(new Error('公钥不存在或无权删除'));

        // 删除公钥
        db.run('DELETE FROM ssh_keys WHERE id = ?', [keyId], (err) => {
          if (err) return reject(err);
          
          // 同步到文件
          syncAuthorizedKeys()
            .then(() => resolve())
            .catch(reject);
        });
      }
    );
  });
}

/**
 * 获取用户的所有公钥
 */
function getUserKeys(fingerprint) {
  return new Promise((resolve, reject) => {
    db.all(
      `SELECT sk.id, sk.public_key, sk.comment, sk.created_at 
       FROM ssh_keys sk 
       JOIN users u ON sk.user_id = u.id 
       WHERE u.fingerprint = ? 
       ORDER BY sk.created_at DESC`,
      [fingerprint],
      (err, rows) => {
        if (err) return reject(err);
        resolve(rows);
      }
    );
  });
}

module.exports = {
  syncAuthorizedKeys,
  validatePublicKey,
  addKey,
  deleteKey,
  getUserKeys
};
