const express = require('express');
const bodyParser = require('body-parser');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');
const config = require('./config');
const db = require('./database');
const keyManager = require('./keyManager');

const app = express();
const PORT = config.server.port;
const HOST = config.server.host;

// 超管会话（内存存储，重启失效）
const adminSessions = new Map();

// 安全中间件
app.use(helmet({
  contentSecurityPolicy: false // 为了加载外部指纹库
}));

// 速率限制
const limiter = rateLimit({
  windowMs: config.security.rateLimitWindowMs,
  max: config.security.rateLimitMaxRequests
});
app.use(limiter);

// 解析 JSON
app.use(bodyParser.json());

// 静态文件
app.use(express.static(path.join(__dirname, 'public')));

// ==================== API 路由 ====================

/**
 * 用户首次访问（注册或验证浏览器指纹）
 */
app.post('/api/auth/init', (req, res) => {
  const { fingerprint } = req.body;

  if (!fingerprint) {
    return res.status(400).json({ error: '缺少浏览器指纹' });
  }

  // 检查用户是否已存在
  db.get('SELECT * FROM users WHERE fingerprint = ?', [fingerprint], (err, user) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: '数据库错误' });
    }

    if (user) {
      // 用户已存在，直接返回
      return res.json({ 
        exists: true,
        message: '请使用认证器输入 6 位验证码' 
      });
    }

    // 新用户，创建用户记录
    db.run(
      'INSERT INTO users (fingerprint) VALUES (?)',
      [fingerprint],
      (err) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: '创建用户失败' });
        }

        res.json({
          exists: false,
          message: '用户已注册，请使用认证器输入 6 位验证码'
        });
      }
    );
  });
});

/**
 * 验证 2FA 代码
 */
app.post('/api/auth/verify', (req, res) => {
  const { fingerprint, token } = req.body;

  if (!fingerprint || !token) {
    return res.status(400).json({ error: '缺少必要参数' });
  }

  // 获取用户
  db.get('SELECT * FROM users WHERE fingerprint = ?', [fingerprint], (err, user) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: '数据库错误' });
    }

    if (!user) {
      return res.status(404).json({ error: '用户不存在' });
    }

    // 获取全局 TOTP 密钥
    db.get('SELECT totp_secret FROM global_totp WHERE id = 1', [], (err, globalTotp) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: '数据库错误' });
      }

      if (!globalTotp) {
        return res.status(500).json({ error: '系统未初始化' });
      }

      // 验证 TOTP
      const verified = speakeasy.totp.verify({
        secret: globalTotp.totp_secret,
        encoding: 'base32',
        token: token,
        window: config.security.totpWindow
      });

      if (verified) {
        res.json({ 
          success: true,
          userId: user.id
        });
      } else {
        res.status(401).json({ error: '验证码错误' });
      }
    });
  });
});

/**
 * 通过令牌访问二维码
 */
app.get('/qrcode/:token', (req, res) => {
  const { token } = req.params;

  // 验证令牌
  db.get('SELECT totp_secret, qr_token FROM global_totp WHERE id = 1', [], (err, globalTotp) => {
    if (err) {
      console.error(err);
      return res.status(500).send('<h1>服务器错误</h1>');
    }

    if (!globalTotp || globalTotp.qr_token !== token) {
      return res.status(404).send('<h1>404 - 无效的二维码链接</h1>');
    }

    // 生成二维码
    const secret = {
      base32: globalTotp.totp_secret,
      otpauth_url: speakeasy.otpauthURL({
        secret: globalTotp.totp_secret,
        encoding: 'base32',
        label: 'SSH Key Manager'
      })
    };

    QRCode.toDataURL(secret.otpauth_url, (err, qrCode) => {
      if (err) {
        console.error(err);
        return res.status(500).send('<h1>生成二维码失败</h1>');
      }

      // 返回 HTML 页面
      const html = `
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>2FA 二维码 - SSH 公钥管理</title>
          <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
              font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Helvetica', 'Arial', sans-serif;
              background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
              min-height: 100vh;
              display: flex;
              align-items: center;
              justify-content: center;
              padding: 20px;
            }
            .container {
              background: white;
              border-radius: 12px;
              padding: 40px;
              max-width: 500px;
              text-align: center;
              box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
            }
            h1 {
              color: #667eea;
              margin-bottom: 20px;
              font-size: 24px;
            }
            .qr-container {
              margin: 30px 0;
              padding: 20px;
              background: #f8f9fa;
              border-radius: 8px;
            }
            .qr-container img {
              max-width: 250px;
              border: 5px solid white;
              border-radius: 8px;
              box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            }
            .hint {
              color: #666;
              font-size: 14px;
              line-height: 1.6;
              margin-top: 20px;
            }
            .warning {
              background: #fff3cd;
              border: 1px solid #ffc107;
              color: #856404;
              padding: 15px;
              border-radius: 8px;
              margin-top: 20px;
              font-size: 14px;
            }
            .steps {
              text-align: left;
              margin-top: 20px;
              padding: 20px;
              background: #f8f9fa;
              border-radius: 8px;
            }
            .steps ol {
              margin-left: 20px;
            }
            .steps li {
              margin: 10px 0;
              color: #333;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>🔐 设置双因素认证</h1>
            <p class="hint">请使用认证器应用扫描下方二维码：</p>
            <div class="qr-container">
              <img src="${qrCode}" alt="2FA QR Code">
            </div>
            <div class="steps">
              <strong>使用步骤：</strong>
              <ol>
                <li>在手机上安装认证器应用（Google Authenticator、Authy 等）</li>
                <li>打开应用，扫描上方二维码</li>
                <li>返回登录页面，输入认证器显示的 6 位验证码</li>
              </ol>
            </div>
            <div class="warning">
              ⚠️ <strong>安全提示：</strong><br>
              请妥善保管此链接，不要分享给他人。建议在设置完成后删除此链接。
            </div>
          </div>
        </body>
        </html>
      `;
      res.send(html);
    });
  });
});

/**
 * 获取用户的所有公钥
 */
app.post('/api/keys/list', async (req, res) => {
  const { fingerprint } = req.body;

  if (!fingerprint) {
    return res.status(400).json({ error: '缺少浏览器指纹' });
  }

  try {
    const keys = await keyManager.getUserKeys(fingerprint);
    res.json({ keys });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: '获取公钥列表失败' });
  }
});

/**
 * 添加公钥
 */
app.post('/api/keys/add', async (req, res) => {
  const { fingerprint, publicKey, comment } = req.body;

  if (!fingerprint || !publicKey) {
    return res.status(400).json({ error: '缺少必要参数' });
  }

  try {
    // 获取用户 ID（支持指纹映射）
    const userId = await keyManager.getActualUserId(fingerprint);
    
    if (!userId) {
      // 用户不存在，创建新用户
      db.run(
        'INSERT INTO users (fingerprint) VALUES (?)',
        [fingerprint],
        async function(err) {
          if (err) {
            console.error(err);
            return res.status(500).json({ error: '创建用户失败' });
          }

          try {
            const result = await keyManager.addKey(this.lastID, fingerprint, publicKey, comment);
            res.json({ 
              success: true,
              keyId: result.id,
              merged: result.merged || false,
              message: result.message || '公钥添加成功' 
            });
          } catch (error) {
            console.error(error);
            res.status(400).json({ error: error.message });
          }
        }
      );
    } else {
      // 用户已存在，直接添加公钥
      try {
        const result = await keyManager.addKey(userId, fingerprint, publicKey, comment);
        res.json({ 
          success: true,
          keyId: result.id,
          merged: result.merged || false,
          message: result.message || '公钥添加成功' 
        });
      } catch (error) {
        console.error(error);
        res.status(400).json({ error: error.message });
      }
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: '添加公钥失败' });
  }
});

/**
 * 删除公钥
 */
app.post('/api/keys/delete', async (req, res) => {
  const { fingerprint, keyId } = req.body;

  if (!fingerprint || !keyId) {
    return res.status(400).json({ error: '缺少必要参数' });
  }

  try {
    await keyManager.deleteKey(keyId, fingerprint);
    res.json({ 
      success: true,
      message: '公钥删除成功' 
    });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: error.message });
  }
});

/**
 * 为指定公钥申请分配 SSH 隧道端口
 */
app.post('/api/keys/allocate-port', async (req, res) => {
  const { fingerprint, keyId } = req.body;

  if (!fingerprint || !keyId) {
    return res.status(400).json({ error: '缺少必要参数' });
  }

  try {
    const userId = await keyManager.getActualUserId(fingerprint);
    if (!userId) {
      return res.status(401).json({ error: '用户不存在' });
    }

    const port = await keyManager.allocateTunnelPort(keyId, userId);
    res.json({
      success: true,
      port,
      message: `已成功分配端口 ${port}`
    });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: error.message });
  }
});

/**
 * 释放指定公钥的 SSH 隧道端口
 */
app.post('/api/keys/release-port', async (req, res) => {
  const { fingerprint, keyId } = req.body;

  if (!fingerprint || !keyId) {
    return res.status(400).json({ error: '缺少必要参数' });
  }

  try {
    const userId = await keyManager.getActualUserId(fingerprint);
    if (!userId) {
      return res.status(401).json({ error: '用户不存在' });
    }

    await keyManager.releaseTunnelPort(keyId, userId);
    res.json({ success: true, message: '端口已释放' });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: error.message });
  }
});

/**
 * 手动为已有公钥设置自定义隧道端口
 */
app.post('/api/keys/set-port', async (req, res) => {
  const { fingerprint, keyId, port } = req.body;

  if (!fingerprint || !keyId || port == null) {
    return res.status(400).json({ error: '缺少必要参数' });
  }

  const portNum = parseInt(port, 10);
  if (!Number.isInteger(portNum) || portNum < 1024 || portNum > 65535) {
    return res.status(400).json({ error: '端口号必须在 1024-65535 之间' });
  }

  try {
    const userId = await keyManager.getActualUserId(fingerprint);
    if (!userId) {
      return res.status(401).json({ error: '用户不存在' });
    }

    await keyManager.setCustomTunnelPort(keyId, userId, portNum);
    res.json({ success: true, port: portNum, message: `端口 ${portNum} 设置成功` });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: error.message });
  }
});

/**
 * 获取当前活跃隧道端口状态
 * 返回：用户所有公钥的端口，以及哪些端口当前处于活跃监听状态
 */
app.post('/api/tunnel/status', async (req, res) => {
  const { fingerprint } = req.body;

  if (!fingerprint) {
    return res.status(400).json({ error: '缺少浏览器指纹' });
  }

  try {
    // 获取用户所有带端口的公钥
    const keys = await keyManager.getUserKeys(fingerprint);
    const allocatedPorts = keys
      .filter(k => k.tunnel_port !== null && k.tunnel_port !== undefined)
      .map(k => k.tunnel_port);

    const { portMin, portMax } = config.tunnel;
    const sshUser = config.ssh.sshUser;
    if (allocatedPorts.length === 0) {
      return res.json({ activePorts: [], portMin, portMax, sshUser });
    }

    // 通过 ss 检测哪些端口当前处于活跃监听状态
    console.log('[DEBUG] tunnel/status allocatedPorts:', allocatedPorts);
    const listeningPorts = await keyManager.getActiveTunnelPorts();
    console.log('[DEBUG] tunnel/status listeningPorts:', [...listeningPorts]);
    const activePorts = allocatedPorts.filter(p => listeningPorts.has(p));
    console.log('[DEBUG] tunnel/status activePorts:', activePorts);

    res.json({ activePorts, portMin, portMax, sshUser });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: '检测隧道状态失败' });
  }
});

/**
 * 设置隔道公开状态（普通用户接口）
 */
app.post('/api/keys/set-public', async (req, res) => {
  const { fingerprint, keyId, isPublic } = req.body;

  if (!fingerprint || keyId == null || isPublic == null) {
    return res.status(400).json({ error: '缺少必要参数' });
  }

  try {
    const userId = await keyManager.getActualUserId(fingerprint);
    if (!userId) return res.status(401).json({ error: '用户不存在' });

    db.run(
      'UPDATE ssh_keys SET is_public = ? WHERE id = ? AND user_id = ? AND tunnel_port IS NOT NULL',
      [isPublic ? 1 : 0, keyId, userId],
      function(err) {
        if (err) return res.status(500).json({ error: '数据库错误' });
        if (this.changes === 0) return res.status(400).json({ error: '公钥不存在、无权操作或未分配隔道端口' });
        res.json({ success: true });
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: '操作失败' });
  }
});

/**
 * 获取所有公开隔道（需登录用户可访问）
 */
app.post('/api/tunnels/public', async (req, res) => {
  const { fingerprint } = req.body;

  if (!fingerprint) {
    return res.status(400).json({ error: '缺少浏览器指纹' });
  }

  try {
    const userId = await keyManager.getActualUserId(fingerprint);
    if (!userId) return res.status(401).json({ error: '请先登录' });

    db.all(
      `SELECT k.id, k.user_id, k.comment, k.tunnel_port, k.created_at,
              u.username, u.fingerprint AS user_fingerprint
       FROM ssh_keys k
       JOIN users u ON k.user_id = u.id
       WHERE k.is_public = 1 AND k.tunnel_port IS NOT NULL
       ORDER BY k.user_id, k.created_at DESC`,
      [],
      async (err, rows) => {
        if (err) return res.status(500).json({ error: '数据库错误' });
        try {
          const listeningPorts = await keyManager.getActiveTunnelPorts();
          const result = rows.map(r => ({
            ...r,
            tunnel_active: listeningPorts.has(r.tunnel_port)
          }));
          res.json({ tunnels: result });
        } catch (e) {
          res.json({ tunnels: rows.map(r => ({ ...r, tunnel_active: false })) });
        }
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: '获取失败' });
  }
});

// ==================== 超管 API 路由 ====================

/**
 * 超管登录
 */
app.post('/api/admin/login', (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ error: '缺少令牌' });
  }

  const adminToken = config.admin && config.admin.token;
  if (!adminToken) {
    return res.status(503).json({ error: '超管功能未启用，请设置 ADMIN_TOKEN 环境变量' });
  }

  if (token !== adminToken) {
    return res.status(401).json({ error: '超管令牌错误' });
  }

  // 生成会话 token
  const sessionToken = crypto.randomBytes(32).toString('hex');
  adminSessions.set(sessionToken, Date.now());

  // 清理超过 24 小时的过期会话
  for (const [k, v] of adminSessions) {
    if (Date.now() - v > 24 * 60 * 60 * 1000) adminSessions.delete(k);
  }

  res.json({ success: true, sessionToken });
});

/**
 * 验证超管会话中间件
 */
function requireAdminSession(req, res, next) {
  const sessionToken = req.body.sessionToken;
  if (!sessionToken || !adminSessions.has(sessionToken)) {
    return res.status(401).json({ error: '超管会话无效，请重新登录' });
  }
  next();
}

/**
 * 获取所有用户的公钥和隧道状态（超管接口）
 */
app.post('/api/admin/all-keys', requireAdminSession, async (req, res) => {
  try {
    const keys = await new Promise((resolve, reject) => {
      db.all(
        `SELECT k.id, k.user_id, k.fingerprint, k.public_key, k.comment,
                k.created_at, k.tunnel_port, k.is_public,
                u.fingerprint AS user_fingerprint, u.username
         FROM ssh_keys k
         JOIN users u ON k.user_id = u.id
         ORDER BY k.user_id, k.created_at DESC`,
        [],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });

    // 获取活跃隧道端口
    const listeningPorts = await keyManager.getActiveTunnelPorts();

    const result = keys.map(k => ({
      ...k,
      tunnel_active: k.tunnel_port != null ? listeningPorts.has(k.tunnel_port) : false,
    }));

    res.json({ keys: result });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: '获取数据失败' });
  }
});

/**
 * 为用户设置可读用户名（超管接口）
 */
app.post('/api/admin/rename-user', requireAdminSession, (req, res) => {
  const { userId, username } = req.body;

  if (!userId) {
    return res.status(400).json({ error: '缺少必要参数' });
  }

  const trimmed = typeof username === 'string' ? username.trim().slice(0, 50) : '';

  db.run(
    'UPDATE users SET username = ? WHERE id = ?',
    [trimmed || null, userId],
    function(err) {
      if (err) return res.status(500).json({ error: '数据库错误' });
      if (this.changes === 0) return res.status(404).json({ error: '用户不存在' });
      res.json({ success: true });
    }
  );
});

/**
 * 删除指定公钥（超管接口）
 */
app.post('/api/admin/delete-key', requireAdminSession, async (req, res) => {
  const { keyId } = req.body;

  if (!keyId) {
    return res.status(400).json({ error: '缺少必要参数' });
  }

  db.run('DELETE FROM ssh_keys WHERE id = ?', [keyId], async function(err) {
    if (err) return res.status(500).json({ error: '数据库错误' });
    if (this.changes === 0) return res.status(404).json({ error: '公钥不存在' });

    try {
      await keyManager.syncAuthorizedKeys();
      res.json({ success: true });
    } catch (e) {
      console.error('同步 authorized_keys 失败:', e);
      res.status(500).json({ error: '公钥已删除，但同步文件失败' });
    }
  });
});

// ==================== 启动服务器 ====================

/**
 * 初始化或获取全局 2FA 密钥
 */
function initializeGlobalTotp(callback) {
  db.get('SELECT totp_secret, qr_token FROM global_totp WHERE id = 1', [], (err, row) => {
    if (err) {
      console.error('数据库错误:', err);
      process.exit(1);
    }

    if (row) {
      // 密钥已存在
      callback(row.totp_secret, row.qr_token, false);
    } else {
      // 生成新的全局 2FA 密钥
      const secret = speakeasy.generateSecret({
        name: 'SSH Key Manager',
        length: 32
      });
      const qrToken = crypto.randomBytes(32).toString('hex');
      
      db.run('INSERT INTO global_totp (id, totp_secret, qr_token) VALUES (1, ?, ?)', 
        [secret.base32, qrToken], (err) => {
        if (err) {
          console.error('创建全局 2FA 密钥失败:', err);
          process.exit(1);
        }
        callback(secret.base32, qrToken, true);
      });
    }
  });
}

app.listen(PORT, HOST, () => {
  console.log(`SSH 公钥管理服务运行在 http://${HOST}:${PORT}`);
  console.log(`可通过以下地址访问：`);
  console.log(`  - http://localhost:${PORT}`);
  console.log(`  - http://<服务器IP>:${PORT}`);
  console.log('');
  
  // 初始化全局 2FA 密钥
  initializeGlobalTotp((totpSecret, qrToken, isNew) => {
    const qrUrl = `http://${HOST}:${PORT}/qrcode/${qrToken}`;
    
    console.log('================================================');
    console.log('🔐 2FA 二维码信息');
    console.log('================================================');
    if (isNew) {
      console.log('⚠️  这是首次启动，已生成全局 2FA 密钥');
    } else {
      console.log('✓ 使用现有 2FA 密钥');
    }
    console.log('');
    console.log('二维码访问链接（请妥善保存）：');
    console.log(`  ${qrUrl}`);
    console.log('');
    console.log('⚠️  重要提示：');
    console.log('  • 将此链接分享给可信用户，供他们扫描二维码');
    console.log('  • 所有用户使用相同的 2FA 密钥，通过浏览器指纹区分身份');
    console.log('  • 建议将链接保存在私有文档中（如私有 Wiki、密码管理器等）');
    console.log('  • 链接丢失后可查看日志或查询数据库获取');
    console.log('================================================');
    console.log('');
    
    console.log(`配置信息：`);
    console.log(`  - 监听地址: ${HOST}`);
    console.log(`  - 监听端口: ${PORT}`);
    console.log(`  - authorized_keys: ${config.ssh.authorizedKeysPath}`);
  });
});

// 优雅关闭
process.on('SIGINT', () => {
  db.close((err) => {
    if (err) {
      console.error(err.message);
    }
    console.log('\n数据库连接已关闭');
    process.exit(0);
  });
});
