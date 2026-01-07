// 全局状态
let visitorId = null;
let isAuthenticated = false;

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
      keysList.innerHTML = data.keys.map(key => `
        <div class="key-item">
          <div class="key-header">
            <div>
              <div class="key-comment">${escapeHtml(key.comment || '无备注')}</div>
              <div class="key-date">添加时间: ${formatDate(key.created_at)}</div>
            </div>
            <button class="btn btn-danger" onclick="deleteKey(${key.id})">删除</button>
          </div>
          <div class="key-content">${escapeHtml(key.public_key)}</div>
        </div>
      `).join('');
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
 * 添加公钥
 */
async function addKey() {
  const publicKeyInput = document.getElementById('public-key-input');
  const commentInput = document.getElementById('key-comment-input');
  const publicKey = publicKeyInput.value.trim();
  const comment = commentInput.value.trim();

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
      // 检查是否发生了指纹合并
      if (data.merged) {
        showSuccess('add-success', data.message || '检测到该公钥已存在，已自动合并您的浏览器指纹！现在您可以管理之前添加的所有 SSH 公钥了！');
      } else {
        showSuccess('add-success', data.message || '公钥添加成功！');
      }
      publicKeyInput.value = '';
      commentInput.value = '';
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
