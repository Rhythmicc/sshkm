# SSH 公钥管理服务

轻量级的 SSH 公钥管理系统，允许多用户在同一服务器上管理各自的 SSH 公钥。可以创建跳板用户（jumpuser），然后用 root 用户启动本服务。

## 创建跳板用户

首先需要创建一个专用的跳板用户，该用户只允许 SSH 公钥认证连接，但不允许登录 shell：

```bash
# 创建跳板用户（使用 nologin shell，禁止登录）
sudo useradd -m -s /usr/sbin/nologin jumpuser

# 或者在某些系统上使用
sudo useradd -m -s /bin/false jumpuser

# 创建 .ssh 目录
sudo mkdir -p /home/jumpuser/.ssh

# 创建空的 authorized_keys 文件
sudo touch /home/jumpuser/.ssh/authorized_keys

# 设置正确的权限（重要！）
sudo chmod 700 /home/jumpuser/.ssh
sudo chmod 600 /home/jumpuser/.ssh/authorized_keys
sudo chown -R jumpuser:jumpuser /home/jumpuser/.ssh
```

**验证跳板用户**：

```bash
# 查看用户信息
id jumpuser

# 查看 authorized_keys 文件权限
ls -la /home/jumpuser/.ssh/
```

## 安装步骤

1. 安装依赖：

```bash
npm install
```

2. 配置服务：

编辑 `ecosystem.config.js` 文件，设置正确的 authorized_keys 路径：

```bash
vim ecosystem.config.js
```

3. 安装并启动服务（使用 PM2）：

```bash
# 安装 PM2
npm install -g pm2
pm2 start ecosystem.config.js
pm2 startup
pm2 save
```

确保 `config.js` 文件安全，不要提交到版本控制系统

- 检查 authorized_keys 文件路径是否正确
- 确保运行服务的用户有权限写入 authorized_keys 文件

3. 常用命令：

```bash
# 查看状态
pm2 status

# 查看日志
pm2 logs ssh-key-manager

# 停止服务
pm2 stop ssh-key-manager

# 重启服务
pm2 restart ssh-key-manager
```

4. 访问服务：

- 本地访问：`http://localhost:3000`
- 局域网访问：`http://<服务器IP>:3000`

## 首次使用

### 1. 获取 2FA 二维码链接

服务启动后，会在控制台输出二维码访问链接：

```
================================================
🔐 2FA 二维码信息
================================================
⚠️  这是首次启动，已生成全局 2FA 密钥

二维码访问链接（请妥善保存）：
  http://localhost:3000/qrcode/abc123def456...

⚠️  重要提示：
  • 将此链接分享给可信用户，供他们扫描二维码
  • 所有用户使用相同的 2FA 密钥，通过浏览器指纹区分身份
  • 建议将链接保存在私有文档中（如私有 Wiki、密码管理器等）
  • 链接丢失后可查看日志或查询数据库获取
================================================
```

**请立即保存二维码链接！**

### 2. 设置 2FA 认证器

1. 访问二维码链接 `http://localhost:3000/qrcode/xxx`
2. 使用手机认证器应用（Google Authenticator、Authy、Microsoft Authenticator 等）扫描二维码
3. 认证器会生成 6 位动态验证码

### 3. 登录系统

1. 访问 `http://localhost:3000`
2. 输入认证器显示的 6 位验证码
3. 验证成功后即可管理 SSH 公钥

## 工作原理

- **全局 2FA 密钥**：所有用户共享同一个 TOTP 密钥
- **用户区分**：通过浏览器指纹自动识别不同用户
- **公钥隔离**：每个用户只能管理自己添加的公钥
- **私有分享**：将二维码链接保存在私有文档中，只有可信用户才能访问

## 安全注意事项

- 二维码链接是访问系统的唯一凭证，请务必妥善保管
- 只分享给可信用户，避免泄露给外部人员
- 建议配置 HTTPS 加密通信
- 定期备份数据库文件 `database.db`
- 不要将二维码链接提交到公开的版本控制系统

## 令牌管理

### 查看二维码链接

如果忘记了二维码链接，可以通过以下方式找回：

1. 查看服务启动日志
2. 或者查询数据库：

```bash
sqlite3 database.db "SELECT qr_token FROM global_totp WHERE id = 1;"
# 输出类似：abc123def456...
# 完整链接：http://your-server:3000/qrcode/abc123def456...
```

### 重置 2FA 密钥

如果二维码链接泄露，需要重新生成：

1. 停止服务：`pm2 stop ssh-key-manager`
2. 删除数据库：`rm database.db`
3. 重启服务：`pm2 start ecosystem.config.js`
4. 保存新的二维码链接并更新私有文档

**注意**：删除数据库会清空所有用户数据和公钥！

## 技术栈

- 后端：Node.js + Express
- 数据库：SQLite
- 2FA：Speakeasy (TOTP)
- 前端：原生 JavaScript + FingerprintJS

## 常见问题

### Q: 二维码链接丢失怎么办？

A: 可以通过查看服务启动日志或直接查询数据库来获取。如果无法找回，只能删除数据库重新生成。

### Q: 多个用户如何使用同一个 2FA？

A: 所有用户扫描同一个二维码后，认证器会生成相同的 6 位验证码。系统通过浏览器指纹自动区分不同用户。

### Q: 如何备份数据？

A: 定期备份 `database.db` 文件即可。该文件包含全局 2FA 密钥、所有用户信息和公钥数据。

### Q: 如何限制访问？

A: 将二维码链接保存在私有文档中（如内部 Wiki、团队 Notion 等），只有能访问该文档的可信用户才能扫描二维码并登录系统。

### Q: 同一个用户在不同浏览器/设备上如何使用？

A: 每个浏览器/设备会被识别为不同用户（不同的浏览器指纹）。可以在不同设备上分别扫描二维码设置 2FA，然后各自添加公钥。

### Q: 公钥会相互覆盖吗？

A: 不会。每个用户（浏览器指纹）的公钥是独立管理的，不会影响其他用户的公钥。
