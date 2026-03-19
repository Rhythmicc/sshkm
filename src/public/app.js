// 全局状态
let visitorId = null;
let isAuthenticated = false;
let activePorts = new Set(); // 当前活跃的隧道端口
let tunnelPollTimer = null; // 轮询定时器
let tunnelPortRange = { min: 20000, max: 29999 }; // 端口分配范围，登录后从服务器同步
let tunnelSshUser = ''; // 跳板机 SSH 用户名，从服务器同步

// 超管状态
let adminSessionToken = null;

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
  
  // 刷新公开隧道列表
  document.getElementById('refresh-public-tunnels-btn').addEventListener('click', loadPublicTunnels);
  
  // 退出登录
  document.getElementById('logout-btn').addEventListener('click', logout);

  // 超管入口
  document.getElementById('admin-entry-btn').addEventListener('click', () => {
    document.getElementById('login-section').style.display = 'none';
    document.getElementById('admin-login-section').style.display = 'block';
    document.getElementById('admin-token-input').focus();
  });
  document.getElementById('admin-back-btn').addEventListener('click', () => {
    document.getElementById('admin-login-section').style.display = 'none';
    document.getElementById('login-section').style.display = 'block';
    hideMessage('admin-auth-error');
  });
  document.getElementById('admin-verify-btn').addEventListener('click', adminLogin);
  document.getElementById('admin-token-input').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') adminLogin();
  });
  document.getElementById('admin-logout-btn').addEventListener('click', adminLogout);
  document.getElementById('admin-refresh-btn').addEventListener('click', loadAdminKeys);
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
  loadPublicTunnels();
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
          <button class="btn ${key.is_public ? 'btn-public-active' : 'btn-public'}" onclick="toggleTunnelPublic(${key.id}, ${key.is_public ? 0 : 1})" title="${key.is_public ? '取消公开此隧道' : '将此隧道公开给其他用户'}">
            ${key.is_public ? '🌐 已公开' : '🔒 设为公开'}
          </button>
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
  const sshUser = tunnelSshUser || 'YOUR_SSH_USER';
  const cmd = `ssh -f -N -R ${port}:localhost:22 ${sshUser}@${serverHost}`;
  navigator.clipboard.writeText(cmd).then(() => {
    showSuccess('add-success', `命令已复制：${cmd}`);
  }).catch(() => {
    prompt('请手动复制以下命令：', `ssh -f -N -R ${port}:localhost:22 ${sshUser}@${serverHost}`);
  });
}

/**
 * 显示 SSH 隧道配置指南弹窗
 */
function showTunnelGuide(port, comment) {
  const serverHost = window.location.hostname;
  const sshUser = tunnelSshUser || 'YOUR_SSH_USER';
  const svcName = `ssh-tunnel-${port}`;
  const cmd = `ssh -f -N -o ServerAliveInterval=60 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes -R ${port}:localhost:22 ${sshUser}@${serverHost}`;
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
        <li>跳板服务：<strong>${serverHost}</strong></li>
      </ul>
    </div>

    <div class="guide-section">
      <h3>① 在远端机器上配置 SSH 密钥免密登录</h3>
      <p>将当前公钥对应的私钥添加到远端机器，确保可免密 SSH 到该服务器：</p>
      <pre class="code-block">ssh-copy-id ${sshUser}@${serverHost}
# 或手动将公钥内容追加到服务器 ~/.ssh/authorized_keys</pre>
    </div>

    <div class="guide-section">
      <h3>② 手动测试隧道连接</h3>
      <p>在远端机器上运行：</p>
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
    &lt;string&gt;-f&lt;/string&gt;
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
      if (data.sshUser) tunnelSshUser = data.sshUser;
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

// ==================== 超管功能 ====================

/**
 * 超管登录
 */
async function adminLogin() {
  const tokenInput = document.getElementById('admin-token-input');
  const token = tokenInput.value.trim();

  if (!token) {
    showError('admin-auth-error', '请输入管理员令牌');
    return;
  }

  try {
    const response = await fetch('/api/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token })
    });

    const data = await response.json();

    if (response.ok && data.success) {
      adminSessionToken = data.sessionToken;
      tokenInput.value = '';
      showAdminPage();
    } else {
      showError('admin-auth-error', data.error || '令牌错误');
      tokenInput.value = '';
    }
  } catch (error) {
    console.error('超管登录失败:', error);
    showError('admin-auth-error', '登录失败，请重试');
  }
}

/**
 * 显示超管仪表板
 */
function showAdminPage() {
  document.getElementById('auth-page').style.display = 'none';
  document.getElementById('admin-page').style.display = 'block';
  loadAdminKeys();
}

/**
 * 退出超管
 */
function adminLogout() {
  adminSessionToken = null;
  document.getElementById('admin-page').style.display = 'none';
  document.getElementById('auth-page').style.display = 'block';
  document.getElementById('admin-login-section').style.display = 'none';
  document.getElementById('login-section').style.display = 'block';
  document.getElementById('admin-keys-list').innerHTML = '';
  document.getElementById('admin-stats').innerHTML = '';
}

/**
 * 加载所有公钥（超管）
 */
async function loadAdminKeys() {
  const listEl = document.getElementById('admin-keys-list');
  const statsEl = document.getElementById('admin-stats');
  listEl.innerHTML = '<div class="loading"><div class="spinner"></div><p>加载中...</p></div>';

  try {
    const response = await fetch('/api/admin/all-keys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sessionToken: adminSessionToken })
    });

    if (response.status === 401) {
      adminLogout();
      return;
    }

    const data = await response.json();
    if (!response.ok) {
      listEl.innerHTML = `<div class="error-message show">${escapeHtml(data.error || '加载失败')}</div>`;
      return;
    }

    const keys = data.keys || [];
    const totalKeys = keys.length;
    const keysWithTunnel = keys.filter(k => k.tunnel_port != null).length;
    const activeTunnels = keys.filter(k => k.tunnel_active).length;
    const uniqueUsers = new Set(keys.map(k => k.user_id)).size;

    statsEl.innerHTML = `
      <div class="admin-stat-grid">
        <div class="admin-stat"><span class="stat-num">${uniqueUsers}</span><span class="stat-label">用户数</span></div>
        <div class="admin-stat"><span class="stat-num">${totalKeys}</span><span class="stat-label">公钥总数</span></div>
        <div class="admin-stat"><span class="stat-num">${keysWithTunnel}</span><span class="stat-label">已分配隧道</span></div>
        <div class="admin-stat"><span class="stat-num admin-stat-active">${activeTunnels}</span><span class="stat-label">活跃隧道</span></div>
      </div>
    `;

    if (keys.length === 0) {
      listEl.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">🔑</div>
          <p>暂无任何公钥数据</p>
        </div>
      `;
      return;
    }

    // 按 user_id 分组
    const groups = {};
    for (const k of keys) {
      if (!groups[k.user_id]) {
        groups[k.user_id] = { fingerprint: k.user_fingerprint, username: k.username || '', keys: [] };
      }
      groups[k.user_id].keys.push(k);
    }

    listEl.innerHTML = Object.entries(groups).map(([userId, group]) => `
      <div class="admin-user-group">
        <div class="admin-user-header">
          <span class="admin-user-label" id="admin-user-label-${userId}">👤 用户 #${userId}${group.username ? ' — ' + escapeHtml(group.username) : ''}</span>
          <span class="admin-user-fp" title="${escapeHtml(group.fingerprint)}">指纹: ${escapeHtml(group.fingerprint.slice(0, 12))}…</span>
          <span class="admin-user-count">${group.keys.length} 个公钥</span>
          <div class="admin-rename-row">
            <input type="text" class="admin-rename-input" id="rename-input-${userId}"
              placeholder="设置用户名（最多50字符）" maxlength="50"
              value="${escapeHtml(group.username)}">
            <button class="btn btn-sm btn-secondary" onclick="adminRenameUser(${userId})">重命名</button>
          </div>
        </div>
        ${group.keys.map(k => renderAdminKeyItem(k)).join('')}
      </div>
    `).join('');

  } catch (error) {
    console.error('加载超管数据失败:', error);
    listEl.innerHTML = '<div class="error-message show">加载失败，请刷新重试</div>';
  }
}

/**
 * 渲染超管视图中的单个公钥条目
 */
function renderAdminKeyItem(key) {
  const hasTunnel = key.tunnel_port != null;
  const tunnelBadge = hasTunnel
    ? `<span class="tunnel-status ${key.tunnel_active ? 'active' : 'inactive'} badge-inline">
         <span class="status-dot"></span>${key.tunnel_active ? '活跃' : '关闭'} :${key.tunnel_port}${key.is_public ? ' 🌐' : ''}
       </span>`
    : `<span class="tunnel-status inactive badge-inline"><span class="status-dot"></span>无隧道</span>`;

  return `
    <div class="key-item admin-key-item">
      <div class="key-header">
        <div>
          <div class="key-comment">${escapeHtml(key.comment || '无备注')}</div>
          <div class="key-date">添加时间: ${formatDate(key.created_at)}</div>
        </div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
          ${tunnelBadge}
          <button class="btn btn-sm btn-danger" onclick="adminDeleteKey(${key.id})">删除</button>
        </div>
      </div>
      <div class="key-content">${escapeHtml(key.public_key)}</div>
    </div>
  `;
}

/**
 * 超管重命名用户
 */
async function adminRenameUser(userId) {
  const input = document.getElementById(`rename-input-${userId}`);
  if (!input) return;
  const username = input.value.trim();

  try {
    const response = await fetch('/api/admin/rename-user', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sessionToken: adminSessionToken, userId, username })
    });
    const data = await response.json();
    if (response.ok && data.success) {
      const label = document.getElementById(`admin-user-label-${userId}`);
      if (label) {
        label.textContent = `👤 用户 #${userId}${username ? ' — ' + username : ''}`;
      }
      alert(`用户 #${userId} 已${username ? '重命名为「' + username + '」' : '清除用户名'}`);
    } else {
      if (response.status === 401) { adminLogout(); return; }
      alert(data.error || '重命名失败');
    }
  } catch (error) {
    console.error('重命名失败:', error);
    alert('重命名失败，请重试');
  }
}

/**
 * 超管删除公钥
 */
async function adminDeleteKey(keyId) {
  if (!confirm('确定要删除这个公钥吗？此操作不可撤销。')) return;

  try {
    const response = await fetch('/api/admin/delete-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sessionToken: adminSessionToken, keyId })
    });
    const data = await response.json();
    if (response.ok && data.success) {
      loadAdminKeys();
    } else {
      if (response.status === 401) { adminLogout(); return; }
      alert(data.error || '删除失败');
    }
  } catch (error) {
    console.error('删除公钥失败:', error);
    alert('删除失败，请重试');
  }
}

// ==================== 隧道公开功能 ====================

/**
 * 切换隧道公开/私有状态
 */
async function toggleTunnelPublic(keyId, isPublic) {
  try {
    const response = await fetch('/api/keys/set-public', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fingerprint: visitorId, keyId, isPublic })
    });
    const data = await response.json();
    if (response.ok && data.success) {
      loadKeys();
      loadPublicTunnels();
      if (isPublic) {
        showSuccess('add-success', '隧道已公开，其他用户现在可以看到并使用此隧道');
      } else {
        showSuccess('add-success', '隧道已设为私有');
      }
    } else {
      alert(data.error || '操作失败');
    }
  } catch (error) {
    console.error('设置公开状态失败:', error);
    alert('操作失败，请重试');
  }
}

/**
 * 加载公开隧道列表
 */
async function loadPublicTunnels() {
  const el = document.getElementById('public-tunnels-list');
  if (!el) return;

  try {
    const response = await fetch('/api/tunnels/public', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fingerprint: visitorId })
    });
    const data = await response.json();
    if (!response.ok) return;

    const tunnels = data.tunnels || [];
    if (tunnels.length === 0) {
      el.innerHTML = '<p class="hint">暂无其他用户公开的隧道</p>';
      return;
    }
    el.innerHTML = tunnels.map(renderPublicTunnelItem).join('');
  } catch (error) {
    console.error('加载公开隧道失败:', error);
  }
}

/**
 * 渲染单个公开隧道条目
 */
function renderPublicTunnelItem(tunnel) {
  const displayName = tunnel.username || `用户 #${tunnel.user_id}`;
  const isActive = tunnel.tunnel_active;

  return `
    <div class="key-item public-tunnel-item">
      <div class="key-header">
        <div>
          <div class="key-comment">${escapeHtml(tunnel.comment || '无备注')}</div>
          <div class="key-date">
            <span class="public-owner">👤 ${escapeHtml(displayName)}</span>
            · 端口: <strong>${tunnel.tunnel_port}</strong>
            · 添加时间: ${formatDate(tunnel.created_at)}
          </div>
        </div>
        <span class="tunnel-status ${isActive ? 'active' : 'inactive'} badge-inline">
          <span class="status-dot"></span>${isActive ? '活跃' : '离线'}
        </span>
      </div>
      <div class="tunnel-actions" style="margin-top:8px;">
        <button class="btn btn-copy" onclick="copyPublicTunnelCmd(${tunnel.tunnel_port})">&#128203; 复制连接命令</button>
      </div>
    </div>
  `;
}

/**
 * 复制通过公开隧道连接的命令
 */
function copyPublicTunnelCmd(port) {
  const serverHost = window.location.hostname;
  const sshUser = tunnelSshUser || 'YOUR_SSH_USER';
  // 跳板命令：先通过 jump server 连接到目标机器（反向隧道在 jump server 上监听 port）
  const cmd = `ssh -J ${sshUser}@${serverHost} -p ${port} <对方用户名>@localhost`;
  navigator.clipboard.writeText(cmd).then(() => {
    showSuccess('add-success', `命令已复制（请将 <对方用户名> 替换为实际用户名）`);
  }).catch(() => {
    prompt('请手动复制以下命令（将 <对方用户名> 替换为实际用户名）：', cmd);
  });
}
