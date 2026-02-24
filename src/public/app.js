// 全局状态
let visitorId = null;
let isAuthenticated = false;
let activePorts = new Set(); // 当前活跃的隧道端口
let tunnelPollTimer = null; // 轮询定时器
let tunnelPortRange = { min: 20000, max: 29999 }; // 端口分配范围，登录后从服务器同步

// 初始化
document.addEventListener('DOMContentLoaded', async () => {
  // 获取浏览器指纹
  await initFingerprint();
  
  // 设置事件监听
  setupEventListeners();
  
  // 初始化认证流程
  await initAuth();
});

/**
 * 初始化浏览器指纹
 */
async function initFingerprint() {
  try {
    const fp = await FingerprintJS.load();
    const result = await fp.get();
    visitorId = result.visitorId;
    console.log('浏览器指纹:', visitorId);
  } catch (error) {
    console.error('获取浏览器指纹失败:', error);
    showError('auth-error', '浏览器指纹识别失败，请刷新页面重试');
  }
}

/**
 * 设置事件监听
 */
function setupEventListeners() {
  // 验证按钮
  document.getElementById('verify-btn').addEventListener('click', verifyToken);
  
  // 回车键验证
  document.getElementById('token-input').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      verifyToken();
    }
  });
  
  // 添加公钥
  document.getElementById('add-key-btn').addEventListener('click', addKey);
  // 刷新隧道状态
  document.getElementById('refresh-status-btn').addEventListener('click', () => {
    loadTunnelStatus(true);
  });
  
  // 退出登录
  document.getElementById('logout-btn').addEventListener('click', logout);
}

/**
 * 初始化认证
 */
async function initAuth() {
  if (!visitorId) {
    showError('auth-error', '浏览器指纹未初始化');
    return;
  }

  try {
    const response = await fetch('/api/auth/init', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fingerprint: visitorId })
    });

    const data = await response.json();

    // 直接显示登录表单
    document.getElementById('login-section').style.display = 'block';
  } catch (error) {
    console.error('初始化认证失败:', error);
    showError('auth-error', '初始化失败，请刷新页面重试');
  }
}

/**
 * 验证 TOTP 令牌
 */
async function verifyToken() {
  const tokenInput = document.getElementById('token-input');
  const token = tokenInput.value.trim();

  if (token.length !== 6 || !/^\d{6}$/.test(token)) {
    showError('auth-error', '请输入 6 位数字验证码');
    return;
  }

  try {
    const response = await fetch('/api/auth/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        fingerprint: visitorId, 
        token: token 
      })
    });

    const data = await response.json();

    if (response.ok && data.success) {
      isAuthenticated = true;
      showManagePage();
    } else {
      showError('auth-error', data.error || '验证码错误，请重试');
      tokenInput.value = '';
    }
  } catch (error) {
    console.error('验证失败:', error);
    showError('auth-error', '验证失败，请重试');
  }
}

/**
 * 显示管理页面
 */
function showManagePage() {
  document.getElementById('auth-page').style.display = 'none';
  document.getElementById('manage-page').style.display = 'block';
  loadKeys();
  // 启动隧道状态轮询（10 秒一次）
  startTunnelPolling();
}

/**
 * 加载公钥列表
 */
async function loadKeys() {
  const keysList = document.getElementById('keys-list');
  keysList.innerHTML = '<div class="loading"><div class="spinner"></div><p>加载中...</p></div>';

  try {
    const response = await fetch('/api/keys/list', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fingerprint: visitorId })
    });

    const data = await response.json();

    if (data.keys && data.keys.length > 0) {
      keysList.innerHTML = data.keys.map(key => renderKeyItem(key)).join('');
      // 加载完公钥后刷新一次隧道状态
      loadTunnelStatus();
    } else {
      keysList.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">🔑</div>
          <p>还没有添加任何公钥</p>
          <p class="hint">在上方添加您的 SSH 公钥开始使用</p>
        </div>
      `;
    }
  } catch (error) {
    console.error('加载公钥失败:', error);
    keysList.innerHTML = '<div class="error-message show">加载失败，请刷新页面重试</div>';
  }
}

/**
 * 渲染单个公钥卡片
 */
function renderKeyItem(key) {
  const hasTunnel = key.tunnel_port !== null && key.tunnel_port !== undefined;
  const isActive = hasTunnel && activePorts.has(key.tunnel_port);

  const tunnelSection = hasTunnel
    ? `
      <div class="tunnel-info">
        <span class="tunnel-status ${isActive ? 'active' : 'inactive'}">
          <span class="status-dot"></span>
          ${isActive ? '隧道活跃' : '隧道关闭'}
        </span>
        <span class="tunnel-port">Port: <strong>${key.tunnel_port}</strong></span>
        <div class="tunnel-actions">
          <button class="btn btn-copy" onclick="copyTunnelCmd(${key.tunnel_port})" title="复制隧道命令">&#128203; 复制命令</button>
          <button class="btn btn-guide" onclick="showTunnelGuide(${key.tunnel_port}, '${escapeJs(key.comment || '')}')">📖 配置指南</button>
          <button class="btn btn-release" onclick="releasePort(${key.id})">释放端口</button>
        </div>
      </div>
    `
    : `
      <div class="tunnel-info tunnel-none">
        <div class="port-assign-row">
          <button class="btn btn-allocate" onclick="allocatePort(${key.id})">系统分配</button>
          <span class="or-divider">或</span>
          <input type="number" class="port-manual-input" id="port-input-${key.id}"
            placeholder="手动填写 (${tunnelPortRange.min}-${tunnelPortRange.max})"
            min="1024" max="65535">
          <button class="btn btn-set-port" onclick="setCustomPort(${key.id})">确认</button>
        </div>
      </div>
    `;

  return `
    <div class="key-item" id="key-item-${key.id}">
      <div class="key-header">
        <div>
          <div class="key-comment">${escapeHtml(key.comment || '无备注')}</div>
          <div class="key-date">添加时间: ${formatDate(key.created_at)}</div>
        </div>
        <button class="btn btn-danger" onclick="deleteKey(${key.id})">删除</button>
      </div>
      <div class="key-content">${escapeHtml(key.public_key)}</div>
      ${tunnelSection}
    </div>
  `;
}

/**
 * 为公钥申请隧道端口
 */
async function allocatePort(keyId) {
  try {
    const response = await fetch('/api/keys/allocate-port', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fingerprint: visitorId, keyId })
    });
    const data = await response.json();
    if (response.ok && data.success) {
      showSuccess('add-success', `已分配端口 ${data.port}！`);
      loadKeys();
    } else {
      alert(data.error || '端口分配失败');
    }
  } catch (error) {
    console.error('端口分配失败:', error);
    alert('端口分配失败，请重试');
  }
}

/**
 * 释放公钥的隧道端口
 */
async function releasePort(keyId) {
  if (!confirm('确定要释放该端口？释放后远端隧道将不再可用。')) return;
  try {
    const response = await fetch('/api/keys/release-port', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fingerprint: visitorId, keyId })
    });
    const data = await response.json();
    if (response.ok && data.success) {
      loadKeys();
    } else {
      alert(data.error || '释放失败');
    }
  } catch (error) {
    console.error('释放端口失败:', error);
    alert('释放失败，请重试');
  }
}

/**
 * 手动设置已有公钥的自定义隧道端口
 */
async function setCustomPort(keyId) {
  const input = document.getElementById(`port-input-${keyId}`);
  if (!input) return;
  const portNum = parseInt(input.value.trim(), 10);

  if (!portNum || portNum < 1024 || portNum > 65535) {
    alert('请输入 1024-65535 之间的有效端口号');
    input.focus();
    return;
  }
  if (portNum < tunnelPortRange.min || portNum > tunnelPortRange.max) {
    if (!confirm(`端口 ${portNum} 不在系统推荐范围 ${tunnelPortRange.min}-${tunnelPortRange.max}，仍要继续吗？`)) {
      input.focus();
      return;
    }
  }

  try {
    const response = await fetch('/api/keys/set-port', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fingerprint: visitorId, keyId, port: portNum })
    });
    const data = await response.json();
    if (response.ok && data.success) {
      showSuccess('add-success', `隧道端口已设置为 ${portNum}`);
      loadKeys();
    } else {
      alert(data.error || '设置失败');
    }
  } catch (error) {
    console.error('设置端口失败:', error);
    alert('设置失败，请重试');
  }
}

/**
 * 复制 SSH 隧道命令到剪贴板
 */
function copyTunnelCmd(port) {
  const serverHost = window.location.hostname;
  const cmd = `ssh -N -R ${port}:localhost:22 user@${serverHost}`;
  navigator.clipboard.writeText(cmd).then(() => {
    showSuccess('add-success', `命令已复制：${cmd}`);
  }).catch(() => {
    prompt('请手动复制以下命令：', `ssh -N -R ${port}:localhost:22 user@${serverHost}`);
  });
}

/**
 * 显示 SSH 隧道配置指南弹窗
 */
function showTunnelGuide(port, comment) {
  const serverHost = window.location.hostname;
  const sshUser = 'YOUR_SSH_USER'; // 用户需替换为实际着陆用户名
  const svcName = `ssh-tunnel-${port}`;
  const cmd = `ssh -N -o ServerAliveInterval=60 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes -R ${port}:localhost:22 ${sshUser}@${serverHost}`;
  const serviceContent = `[Unit]
Description=SSH Reverse Tunnel (port ${port}${comment ? ' - ' + comment : ''})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${sshUser}
Restart=always
RestartSec=30
ExecStart=/usr/bin/ssh -N \\
  -o ServerAliveInterval=60 \\
  -o ServerAliveCountMax=3 \\
  -o ExitOnForwardFailure=yes \\
  -o StrictHostKeyChecking=no \\
  -R ${port}:localhost:22 \\
  ${sshUser}@${serverHost}

[Install]
WantedBy=multi-user.target`;

  document.getElementById('tunnel-guide-content').innerHTML = `
    <div class="guide-section">
      <h3>📌 信息</h3>
      <ul>
        <li>公钥备注：<strong>${escapeHtml(comment || '无')}</strong></li>
        <li>分配端口：<strong>${port}</strong></li>
        <li>足跳山服务器：<strong>${serverHost}</strong></li>
      </ul>
    </div>

    <div class="guide-section">
      <h3>① 在远端机器上配置 SSH 密阥免密登录</h3>
      <p>将当前公钥对应的私钥添加到远端机器，确保可免密 SSH 到该服务器：</p>
      <pre class="code-block">ssh-copy-id ${sshUser}@${serverHost}
# 或手动将公钥内容追加到服务器 ~/.ssh/authorized_keys</pre>
    </div>

    <div class="guide-section">
      <h3>② 手动测试隧道连接</h3>
      <p>在20000 和 30000-... 等高位端口的神奇尔服务器，在远端机器上运行：</p>
      <div class="copy-wrap">
        <pre class="code-block" id="guide-cmd">${escapeHtml(cmd)}</pre>
        <button class="btn btn-copy guide-copy-btn" onclick="copyText('guide-cmd')">📋 复制</button>
      </div>
      <p class="guide-note">成功后，页面左上角状态标志将变为 <span class="badge-active">隧道活跃</span>。</p>
    </div>

    <div class="guide-section">
      <h3>③ 配置 systemd 开机自启（Linux）</h3>
      <p>1）保存以下内容到 <code>/etc/systemd/system/${svcName}.service</code>（将 <code>${sshUser}</code> 替换为实际用户名）：</p>
      <div class="copy-wrap">
        <pre class="code-block" id="guide-service">${escapeHtml(serviceContent)}</pre>
        <button class="btn btn-copy guide-copy-btn" onclick="copyText('guide-service')">📋 复制</button>
      </div>
      <p>2）启动并设为开机自启：</p>
      <div class="copy-wrap">
        <pre class="code-block" id="guide-enable">sudo systemctl daemon-reload
sudo systemctl enable --now ${svcName}.service
sudo systemctl status ${svcName}.service</pre>
        <button class="btn btn-copy guide-copy-btn" onclick="copyText('guide-enable')">📋 复制</button>
      </div>
    </div>

    <div class="guide-section">
      <h3>④ macOS 开机自启（launchd）</h3>
      <p>保存以下内容到 <code>~/Library/LaunchAgents/com.ssh.tunnel.${port}.plist</code>：</p>
      <div class="copy-wrap">
        <pre class="code-block" id="guide-plist">&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd"&gt;
&lt;plist version="1.0"&gt;
&lt;dict&gt;
  &lt;key&gt;Label&lt;/key&gt;
  &lt;string&gt;com.ssh.tunnel.${port}&lt;/string&gt;
  &lt;key&gt;ProgramArguments&lt;/key&gt;
  &lt;array&gt;
    &lt;string&gt;/usr/bin/ssh&lt;/string&gt;
    &lt;string&gt;-N&lt;/string&gt;
    &lt;string&gt;-o&lt;/string&gt;&lt;string&gt;ServerAliveInterval=60&lt;/string&gt;
    &lt;string&gt;-o&lt;/string&gt;&lt;string&gt;ServerAliveCountMax=3&lt;/string&gt;
    &lt;string&gt;-o&lt;/string&gt;&lt;string&gt;ExitOnForwardFailure=yes&lt;/string&gt;
    &lt;string&gt;-R&lt;/string&gt;&lt;string&gt;${port}:localhost:22&lt;/string&gt;
    &lt;string&gt;${sshUser}@${serverHost}&lt;/string&gt;
  &lt;/array&gt;
  &lt;key&gt;RunAtLoad&lt;/key&gt;&lt;true/&gt;
  &lt;key&gt;KeepAlive&lt;/key&gt;&lt;true/&gt;
  &lt;key&gt;ThrottleInterval&lt;/key&gt;&lt;integer&gt;30&lt;/integer&gt;
&lt;/dict&gt;
&lt;/plist&gt;</pre>
        <button class="btn btn-copy guide-copy-btn" onclick="copyText('guide-plist')">📋 复制</button>
      </div>
      <div class="copy-wrap">
        <pre class="code-block" id="guide-launchctl">launchctl load ~/Library/LaunchAgents/com.ssh.tunnel.${port}.plist</pre>
        <button class="btn btn-copy guide-copy-btn" onclick="copyText('guide-launchctl')">📋 复制</button>
      </div>
    </div>
  `;

  document.getElementById('tunnel-guide-modal').style.display = 'flex';
  document.body.style.overflow = 'hidden';
}

/**
 * 关闭指南弹窗
 */
function closeTunnelGuide(event) {
  // 点击蒙层关闭，点击内容区不关闭
  if (event && event.target !== document.getElementById('tunnel-guide-modal')) return;
  document.getElementById('tunnel-guide-modal').style.display = 'none';
  document.body.style.overflow = '';
}

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeTunnelGuide();
});

/**
 * 复制指定元素的文本内容
 */
function copyText(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  navigator.clipboard.writeText(el.textContent).then(() => {
    const btn = el.nextElementSibling;
    if (btn) { const orig = btn.textContent; btn.textContent = '✓ 已复制'; setTimeout(() => btn.textContent = orig, 2000); }
  }).catch(() => {
    const r = document.createRange();
    r.selectNode(el);
    window.getSelection().removeAllRanges();
    window.getSelection().addRange(r);
  });
}

/**
 * escapeJs — 安全内嵌到 HTML 属性字符串里
 */
function escapeJs(text) {
  return String(text).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '&quot;');
}

/**
 * 加载隧道状态，并更新 UI 中的活跃标志
 */
async function loadTunnelStatus(showFeedback = false) {
  try {
    const response = await fetch('/api/tunnel/status', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fingerprint: visitorId })
    });
    const data = await response.json();
    if (response.ok) {
      activePorts = new Set(data.activePorts);
      // 同步端口范围
      if (data.portMin) tunnelPortRange = { min: data.portMin, max: data.portMax };
      // 更新已渲染公钥卡片中的状态指示（只更新 DOM，不重新渲染整个列表）
      document.querySelectorAll('.tunnel-status').forEach(el => {
        const portEl = el.closest('.tunnel-info').querySelector('.tunnel-port strong');
        if (!portEl) return;
        const port = parseInt(portEl.textContent, 10);
        const isActive = activePorts.has(port);
        el.className = `tunnel-status ${isActive ? 'active' : 'inactive'}`;
        el.querySelector('.status-dot') && (el.innerHTML = `<span class="status-dot"></span>${isActive ? '隧道活跃' : '隧道关闭'}`);
      });
      if (showFeedback) {
        showSuccess('add-success', `状态已刷新，当前活跃隧道端口：${activePorts.size > 0 ? [...activePorts].join(', ') : '无'}`);      }
    }
  } catch (error) {
    console.error('获取隧道状态失败:', error);
  }
}

/**
 * 启动隧道状态轮询
 */
function startTunnelPolling() {
  stopTunnelPolling();
  tunnelPollTimer = setInterval(() => {
    if (isAuthenticated) loadTunnelStatus();
  }, 10000); // 每 10 秒轮询一次
}

/**
 * 停止轮询
 */
function stopTunnelPolling() {
  if (tunnelPollTimer) {
    clearInterval(tunnelPollTimer);
    tunnelPollTimer = null;
  }
}

/**
 * 添加公钥
 */
async function addKey() {
  const publicKeyInput = document.getElementById('public-key-input');
  const commentInput = document.getElementById('key-comment-input');
  const requestPortCheckbox = document.getElementById('request-port-checkbox');
  const publicKey = publicKeyInput.value.trim();
  const comment = commentInput.value.trim();
  const requestPort = requestPortCheckbox.checked;

  hideMessage('add-error');
  hideMessage('add-success');

  if (!publicKey) {
    showError('add-error', '请输入公钥内容');
    return;
  }

  try {
    const response = await fetch('/api/keys/add', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        fingerprint: visitorId, 
        publicKey: publicKey,
        comment: comment
      })
    });

    const data = await response.json();

    if (response.ok && data.success) {
      let successMsg = data.message || '公钥添加成功！';
      // 公钥添加成功后，如果用户勾选了申请端口，自动分配
      if (requestPort && data.keyId && !data.merged) {
        try {
          const portResp = await fetch('/api/keys/allocate-port', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ fingerprint: visitorId, keyId: data.keyId })
          });
          const portData = await portResp.json();
          if (portResp.ok && portData.success) {
            successMsg += `\n已自动分配隧道端口: ${portData.port}`;
          } else {
            successMsg += `\n端口分配失败: ${portData.error || '未知错误'}`;
          }
        } catch (e) {
          successMsg += '\n自动分配端口失败';
        }
      }
      if (data.merged) {
        showSuccess('add-success', data.message || '检测到该公钥已存在，已自动合并您的浏览器指纹！现在您可以管理之前添加的所有 SSH 公钥了！');
      } else {
        showSuccess('add-success', successMsg);
      }
      publicKeyInput.value = '';
      commentInput.value = '';
      requestPortCheckbox.checked = false;
      loadKeys();
    } else {
      showError('add-error', data.error || '添加失败');
    }
  } catch (error) {
    console.error('添加公钥失败:', error);
    showError('add-error', '添加失败，请重试');
  }
}

/**
 * 删除公钥
 */
async function deleteKey(keyId) {
  if (!confirm('确定要删除这个公钥吗？此操作不可撤销。')) {
    return;
  }

  try {
    const response = await fetch('/api/keys/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        fingerprint: visitorId, 
        keyId: keyId 
      })
    });

    const data = await response.json();

    if (response.ok && data.success) {
      loadKeys();
    } else {
      alert(data.error || '删除失败');
    }
  } catch (error) {
    console.error('删除公钥失败:', error);
    alert('删除失败，请重试');
  }
}

/**
 * 退出登录
 */
function logout() {
  isAuthenticated = false;
  stopTunnelPolling();
  activePorts = new Set();
  document.getElementById('manage-page').style.display = 'none';
  document.getElementById('auth-page').style.display = 'block';
  document.getElementById('token-input').value = '';
  hideMessage('auth-error');
}

/**
 * 显示错误消息
 */
function showError(elementId, message) {
  const element = document.getElementById(elementId);
  element.textContent = message;
  element.classList.add('show');
}

/**
 * 显示成功消息
 */
function showSuccess(elementId, message) {
  const element = document.getElementById(elementId);
  element.textContent = message;
  element.classList.add('show');
  
  // 3秒后自动隐藏
  setTimeout(() => {
    hideMessage(elementId);
  }, 3000);
}

/**
 * 隐藏消息
 */
function hideMessage(elementId) {
  const element = document.getElementById(elementId);
  element.classList.remove('show');
}

/**
 * HTML 转义
 */
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/**
 * 格式化日期
 */
function formatDate(dateString) {
  const date = new Date(dateString);
  return date.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  });
}
