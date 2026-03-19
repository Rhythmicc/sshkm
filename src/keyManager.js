const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const config = require('./config');
const db = require('./database');

const AUTHORIZED_KEYS_PATH = config.ssh.authorizedKeysPath;

/**
 * 同步所有公钥到 authorized_keys 文件
 */
function syncAuthorizedKeys() {
  return new Promise((resolve, reject) => {
    // 获取所有公钥（含已分配的隧道端口，用于生成 permitlisten 限制）
    db.all('SELECT public_key, comment, tunnel_port FROM ssh_keys ORDER BY id', [], (err, rows) => {
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
        // 已分配端口的公钥加上 permitlisten="PORT"，只允许在该端口上建立反向隧道，防止端口冲突
        const content = rows.map(row => {
          const comment = row.comment ? ` ${row.comment}` : '';
          const options = row.tunnel_port ? `permitlisten="${row.tunnel_port}" ` : '';
          return `${options}${row.public_key}${comment}`;
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
 * 根据指纹获取实际的用户ID（支持指纹映射）
 */
function getActualUserId(fingerprint) {
  return new Promise((resolve, reject) => {
    // 先尝试从指纹映射表查找
    db.get(
      'SELECT user_id FROM fingerprint_mapping WHERE fingerprint = ?',
      [fingerprint],
      (err, mapping) => {
        if (err) return reject(err);
        if (mapping) {
          return resolve(mapping.user_id);
        }
        
        // 如果没有映射，则从用户表查找
        db.get(
          'SELECT id FROM users WHERE fingerprint = ?',
          [fingerprint],
          (err, user) => {
            if (err) return reject(err);
            resolve(user ? user.id : null);
          }
        );
      }
    );
  });
}

/**
 * 合并指纹（将新指纹映射到已有用户）
 */
function mergeFingerprints(existingUserId, newFingerprint) {
  return new Promise((resolve, reject) => {
    // 插入指纹映射
    db.run(
      'INSERT INTO fingerprint_mapping (user_id, fingerprint, is_primary) VALUES (?, ?, 0)',
      [existingUserId, newFingerprint],
      (err) => {
        if (err) return reject(err);
        console.log(`已合并指纹: ${newFingerprint} -> 用户ID: ${existingUserId}`);
        resolve();
      }
    );
  });
}

/**
 * 检查公钥是否存在，如果存在返回其用户ID
 */
function checkKeyExists(publicKey) {
  return new Promise((resolve, reject) => {
    db.get(
      'SELECT user_id FROM ssh_keys WHERE public_key = ?',
      [publicKey],
      (err, row) => {
        if (err) return reject(err);
        resolve(row ? row.user_id : null);
      }
    );
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
 * 添加公钥（支持自动合并指纹）
 */
function addKey(userId, fingerprint, publicKey, comment) {
  return new Promise(async (resolve, reject) => {
    const trimmedKey = publicKey.trim();
    
    if (!validatePublicKey(trimmedKey)) {
      return reject(new Error('无效的公钥格式'));
    }

    try {
      // 检查公钥是否已存在
      const existingUserId = await checkKeyExists(trimmedKey);
      
      if (existingUserId) {
        // 公钥已存在
        if (existingUserId === userId) {
          // 同一用户重复添加
          return reject(new Error('该公钥已存在'));
        } else {
          // 不同指纹的用户添加了已存在的公钥，执行指纹合并
          try {
            await mergeFingerprints(existingUserId, fingerprint);
            return resolve({ 
              id: null, 
              merged: true,
              existingUserId: existingUserId,
              message: '检测到该公钥已存在，已自动合并您的浏览器指纹。现在您可以管理之前添加的所有 SSH 公钥了！'
            });
          } catch (mergeError) {
            // 如果指纹已经映射过，说明已经合并过了
            if (mergeError.message.includes('UNIQUE constraint failed')) {
              return reject(new Error('该公钥已存在'));
            }
            return reject(mergeError);
          }
        }
      }

      // 公钥不存在，正常添加
      db.run(
        'INSERT INTO ssh_keys (user_id, fingerprint, public_key, comment) VALUES (?, ?, ?, ?)',
        [userId, fingerprint, trimmedKey, comment],
        function(err) {
          if (err) return reject(err);
          
          // 同步到文件
          syncAuthorizedKeys()
            .then(() => resolve({ id: this.lastID, merged: false }))
            .catch(reject);
        }
      );
    } catch (error) {
      reject(error);
    }
  });
}

/**
 * 删除公钥（只能删除自己添加的，支持指纹映射）
 */
function deleteKey(keyId, fingerprint) {
  return new Promise(async (resolve, reject) => {
    try {
      const userId = await getActualUserId(fingerprint);
      if (!userId) {
        return reject(new Error('用户不存在'));
      }

      // 先验证这个公钥是否属于该用户
      db.get(
        'SELECT id FROM ssh_keys WHERE id = ? AND user_id = ?',
        [keyId, userId],
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
    } catch (error) {
      reject(error);
    }
  });
}

/**
 * 获取用户的所有公钥（支持指纹映射）
 */
function getUserKeys(fingerprint) {
  return new Promise(async (resolve, reject) => {
    try {
      const userId = await getActualUserId(fingerprint);
      if (!userId) {
        return resolve([]);
      }

      db.all(
        `SELECT sk.id, sk.public_key, sk.comment, sk.created_at, sk.tunnel_port
         FROM ssh_keys sk 
         WHERE sk.user_id = ? 
         ORDER BY sk.created_at DESC`,
        [userId],
        (err, rows) => {
          if (err) return reject(err);
          resolve(rows);
        }
      );
    } catch (error) {
      reject(error);
    }
  });
}

/**
 * 分配一个可用端口给指定公钥（需已验证用户所有权）
 */
function allocateTunnelPort(keyId, userId) {
  return new Promise((resolve, reject) => {
    const { portMin, portMax } = config.tunnel;

    // 查询当前已占用的所有端口
    db.all(
      'SELECT tunnel_port FROM ssh_keys WHERE tunnel_port IS NOT NULL',
      [],
      (err, rows) => {
        if (err) return reject(err);

        const usedPorts = new Set(rows.map(r => r.tunnel_port));
        let assignedPort = null;
        for (let p = portMin; p <= portMax; p++) {
          if (!usedPorts.has(p)) {
            assignedPort = p;
            break;
          }
        }

        if (assignedPort === null) {
          return reject(new Error(`端口池已耗尽（${portMin}-${portMax}）`));
        }

        // 验证公钥属于该用户，同时更新
        db.run(
          'UPDATE ssh_keys SET tunnel_port = ? WHERE id = ? AND user_id = ?',
          [assignedPort, keyId, userId],
          function(err) {
            if (err) return reject(err);
            if (this.changes === 0) return reject(new Error('公钥不存在或无权操作'));
            // 重新同步 authorized_keys，使 permitlisten 生效
            syncAuthorizedKeys()
              .then(() => resolve(assignedPort))
              .catch(() => resolve(assignedPort)); // 端口已分配，同步失败不影响返回
          }
        );
      }
    );
  });
}

/**
 * 手动设置自定义隧道端口（仅限已有公钥、未分配端口时）
 * 检查：端口未被占用、属于该用户、公钥当前无端口
 */
function setCustomTunnelPort(keyId, userId, port) {
  return new Promise((resolve, reject) => {
    // 检查端口是否已被占用（排除当前公钥自身）
    db.get(
      'SELECT id FROM ssh_keys WHERE tunnel_port = ? AND id != ?',
      [port, keyId],
      (err, conflict) => {
        if (err) return reject(err);
        if (conflict) return reject(new Error(`端口 ${port} 已被其他公钥占用`));

        // 硾认公钥属于该用户且当前未分配端口
        db.run(
          'UPDATE ssh_keys SET tunnel_port = ? WHERE id = ? AND user_id = ? AND tunnel_port IS NULL',
          [port, keyId, userId],
          function(err) {
            if (err) {
              // UNIQUE 冲突（并发情况）
              if (err.message && err.message.includes('UNIQUE')) {
                return reject(new Error(`端口 ${port} 已被占用`));
              }
              return reject(err);
            }
            if (this.changes === 0) {
              return reject(new Error('公钥不存在、无权操作或已分配了端口'));
            }
            // 重新同步 authorized_keys，使 permitlisten 生效
            syncAuthorizedKeys().then(resolve).catch(resolve);
          }
        );
      }
    );
  });
}

/**
 * 释放指定公钥的隧道端口
 */
function releaseTunnelPort(keyId, userId) {
  return new Promise((resolve, reject) => {
    db.run(
      'UPDATE ssh_keys SET tunnel_port = NULL WHERE id = ? AND user_id = ?',
      [keyId, userId],
      function(err) {
        if (err) return reject(err);
        if (this.changes === 0) return reject(new Error('公钥不存在或无权操作'));
        // 重新同步 authorized_keys，移除 permitlisten 限制
        syncAuthorizedKeys().then(resolve).catch(resolve);
      }
    );
  });
}

/**
 * 超管：删除任意公钥（无所有权检查）
 */
function adminDeleteKey(keyId) {
  return new Promise((resolve, reject) => {
    db.run('DELETE FROM ssh_keys WHERE id = ?', [keyId], function(err) {
      if (err) return reject(err);
      if (this.changes === 0) return reject(new Error('公钥不存在'));
      syncAuthorizedKeys().then(resolve).catch(reject);
    });
  });
}

/**
 * 超管：设置用户显示名称
 */
function setUserDisplayName(userId, displayName) {
  return new Promise((resolve, reject) => {
    db.run(
      'UPDATE users SET display_name = ? WHERE id = ?',
      [displayName && displayName.trim() ? displayName.trim() : null, userId],
      function(err) {
        if (err) return reject(err);
        if (this.changes === 0) return reject(new Error('用户不存在'));
        resolve();
      }
    );
  });
}

/**
 * 通过 ss 命令检测当前处于监听状态的端口集合（即活跃 SSH 隧道）
 */
function getActiveTunnelPorts() {
  return new Promise((resolve) => {
    exec('ss -tulpn | grep sshd', (err, stdout, stderr) => {
      console.log('[DEBUG] ss -tulpn err:', err ? err.message : null);
      console.log('[DEBUG] ss -tulpn stderr:', stderr);
      console.log('[DEBUG] ss -tulpn stdout:\n' + stdout);
      if (err) {
        exec('netstat -tlnp 2>/dev/null || netstat -anp tcp 2>/dev/null', (err2, stdout2, stderr2) => {
          console.log('[DEBUG] netstat err:', err2 ? err2.message : null);
          console.log('[DEBUG] netstat stdout:\n' + stdout2);
          if (err2) return resolve(new Set());
          const result = parseListeningPorts(stdout2);
          console.log('[DEBUG] parseListeningPorts result (netstat):', [...result]);
          resolve(result);
        });
        return;
      }
      const result = parseListeningPorts(stdout);
      console.log('[DEBUG] parseListeningPorts result (ss):', [...result]);
      resolve(result);
    });
  });
}

/**
 * 解析 ss/netstat 输出，提取 sshd 监听的端口号集合
 * ss 输出格式（-tulpn）：
 *   tcp  LISTEN  0  128  0.0.0.0:6000  0.0.0.0:*  users:(("sshd",pid=...,fd=...))
 * - 有进程信息（root 运行）时只取 sshd 行，精确识别反向隧道
 * - 无进程信息（非 root）时取所有 LISTEN 行，由调用方的端口列表交集过滤
 * IPv4/IPv6 重复行由 Set 自动去重
 */
function parseListeningPorts(output) {
  const ports = new Set();
  const hasProcInfo = output.includes('sshd');
  console.log('[DEBUG] parseListeningPorts: hasProcInfo =', hasProcInfo);

  for (const line of output.split('\n')) {
    if (hasProcInfo) {
      if (!line.includes('sshd')) continue;
    } else {
      if (!line.includes('LISTEN')) continue;
    }
    console.log('[DEBUG] matched line:', JSON.stringify(line));
    const fields = line.trim().split(/\s+/);
    console.log('[DEBUG] fields:', fields);
    const localAddr = fields[4];
    if (!localAddr) { console.log('[DEBUG] no localAddr, skip'); continue; }
    const port = parseInt(localAddr.split(':').pop(), 10);
    console.log('[DEBUG] localAddr:', localAddr, '-> port:', port);
    if (Number.isInteger(port) && port > 0 && port <= 65535) {
      ports.add(port);
    }
  }
  return ports;
}

module.exports = {
  syncAuthorizedKeys,
  validatePublicKey,
  addKey,
  deleteKey,
  getUserKeys,
  getActualUserId,
  mergeFingerprints,
  checkKeyExists,
  allocateTunnelPort,
  releaseTunnelPort,
  getActiveTunnelPorts,
  setCustomTunnelPort,
  adminDeleteKey,
  setUserDisplayName,
};
