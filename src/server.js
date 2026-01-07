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
