/**
 * relayManager.js — NAT 穿透中继管理器
 *
 * 支持协议：
 *   - ssh  : 基于 OpenSSH 反向隧道（现有机制，仅做端口注册）
 *   - tcp  : 纯 Node.js TCP 反向代理（客户端主动连入控制通道）
 *   - udp  : UDP over TCP 中继（客户端维持 TCP 控制通道，封包转发）
 *
 * TCP 工作原理：
 *   1. 客户端携带 token 连接控制端口（/api/relay/connect）
 *   2. server 在分配的 listen_port 上创建 TCP 服务器
 *   3. 外部连接到 listen_port 时，通过控制通道通知客户端建立数据通道
 *   4. 数据在外部连接 ↔ 客户端数据通道间双向转发
 *
 * UDP 工作原理：
 *   1. 客户端保持 TCP 控制通道心跳
 *   2. server 在分配的 listen_port 上监听 UDP
 *   3. 收到 UDP 包后封装成消息通过 TCP 控制通道推送给客户端
 *   4. 客户端解包后发给本地服务，响应反向封装后送回
 */

'use strict';

const net = require('net');
const dgram = require('dgram');
const crypto = require('crypto');
const config = require('./config');
const db = require('./database');

// ==================== 内存状态 ====================

/** 已激活的 TCP 中继服务器 Map<listen_port, net.Server> */
const tcpServers = new Map();

/** 已连接的中继客户端 Map<token, RelayClient> */
const relayClients = new Map();

/** relay_client_id → token 快查表 */
const clientIdToToken = new Map();

/** 已激活的 UDP 中继 Map<listen_port, dgram.Socket> */
const udpSockets = new Map();

// ==================== 数据库辅助 ====================

function dbGet(sql, params) {
  return new Promise((resolve, reject) =>
    db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)))
  );
}

function dbAll(sql, params) {
  return new Promise((resolve, reject) =>
    db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)))
  );
}

function dbRun(sql, params) {
  return new Promise((resolve, reject) =>
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve({ lastID: this.lastID, changes: this.changes });
    })
  );
}

// ==================== 客户端注册 ====================

/**
 * 为指定用户创建中继客户端（生成唯一 token）
 */
async function createRelayClient(userId, name) {
  const token = crypto.randomBytes(32).toString('hex');
  const result = await dbRun(
    'INSERT INTO relay_clients (user_id, name, token) VALUES (?, ?, ?)',
    [userId, name || null, token]
  );
  return { id: result.lastID, token };
}

/**
 * 删除中继客户端（同时关闭其所有活跃中继）
 */
async function deleteRelayClient(clientId, userId) {
  const client = await dbGet(
    'SELECT id FROM relay_clients WHERE id = ? AND user_id = ?',
    [clientId, userId]
  );
  if (!client) throw new Error('客户端不存在或无权操作');

  // 关闭该客户端所有活跃中继服务器
  const rules = await dbAll(
    'SELECT listen_port FROM relay_rules WHERE relay_client_id = ? AND enabled = 1',
    [clientId]
  );
  for (const rule of rules) {
    stopTcpServer(rule.listen_port);
    stopUdpSocket(rule.listen_port);
  }

  await dbRun('DELETE FROM relay_clients WHERE id = ?', [clientId]);
}

/**
 * 获取用户的所有中继客户端
 */
function getUserRelayClients(userId) {
  return dbAll(
    `SELECT rc.id, rc.name, rc.token, rc.last_seen, rc.created_at,
            (SELECT COUNT(*) FROM relay_rules rr WHERE rr.relay_client_id = rc.id) AS rule_count
     FROM relay_clients rc WHERE rc.user_id = ? ORDER BY rc.created_at DESC`,
    [userId]
  );
}

// ==================== 规则管理 ====================

/**
 * 分配端口并创建转发规则
 * @param {Object} opts - { userId, relayClientId, protocol, targetHost, targetPort, name }
 */
async function createRelayRule(opts) {
  const { userId, relayClientId, protocol, targetHost, targetPort, name } = opts;

  // 从统一端口池中找一个未被占用的端口
  const { portMin, portMax } = config.relay;
  const usedRows = await dbAll('SELECT listen_port FROM relay_rules', []);
  const used = new Set(usedRows.map(r => r.listen_port));

  // SSH 隧道也占用端口池，需一并检查
  const sshRows = await dbAll('SELECT tunnel_port FROM ssh_keys WHERE tunnel_port IS NOT NULL', []);
  for (const r of sshRows) used.add(r.tunnel_port);

  let port = null;
  for (let p = portMin; p <= portMax; p++) {
    if (!used.has(p)) { port = p; break; }
  }
  if (port === null) throw new Error(`端口池已耗尽（${portMin}-${portMax}）`);

  const result = await dbRun(
    `INSERT INTO relay_rules
       (user_id, relay_client_id, protocol, listen_port, target_host, target_port, name)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [userId, relayClientId || null, protocol || 'tcp', port,
     targetHost || 'localhost', targetPort || null, name || null]
  );

  // 如果是 TCP 并且对应客户端已连接，立即启动中继服务器
  if (protocol === 'tcp' && relayClientId) {
    const token = clientIdToToken.get(relayClientId);
    if (token && relayClients.has(token)) {
      startTcpRelayServer(port, token);
    }
  }
  // UDP 同理
  if (protocol === 'udp' && relayClientId) {
    const token = clientIdToToken.get(relayClientId);
    if (token && relayClients.has(token)) {
      startUdpRelay(port, token);
    }
  }

  return { id: result.lastID, port };
}

/**
 * 删除转发规则
 */
async function deleteRelayRule(ruleId, userId) {
  const rule = await dbGet(
    'SELECT listen_port FROM relay_rules WHERE id = ? AND user_id = ?',
    [ruleId, userId]
  );
  if (!rule) throw new Error('规则不存在或无权操作');
  stopTcpServer(rule.listen_port);
  stopUdpSocket(rule.listen_port);
  await dbRun('DELETE FROM relay_rules WHERE id = ?', [ruleId]);
}

/**
 * 获取用户的所有转发规则（含活跃状态）
 */
async function getUserRelayRules(userId) {
  const rows = await dbAll(
    `SELECT rr.*, rc.name AS client_name
     FROM relay_rules rr
     LEFT JOIN relay_clients rc ON rr.relay_client_id = rc.id
     WHERE rr.user_id = ? ORDER BY rr.created_at DESC`,
    [userId]
  );
  return rows.map(r => ({
    ...r,
    active: r.protocol === 'tcp' ? tcpServers.has(r.listen_port)
           : r.protocol === 'udp' ? udpSockets.has(r.listen_port)
           : false, // SSH 活跃状态由 keyManager.getActiveTunnelPorts 处理
  }));
}

// ==================== TCP 中继服务器 ====================

/**
 * 启动 TCP 中继服务器（listen_port → 通过控制通道转发给客户端）
 */
function startTcpRelayServer(port, clientToken) {
  if (tcpServers.has(port)) return; // 已在运行

  const server = net.createServer(async (externalConn) => {
    const client = relayClients.get(clientToken);
    if (!client || !client.controlSocket || client.controlSocket.destroyed) {
      externalConn.destroy();
      return;
    }

    // 通知客户端新连接到来（发送控制消息：NEW_CONN <connId>）
    const connId = crypto.randomBytes(8).toString('hex');
    sendControl(client.controlSocket, { type: 'NEW_CONN', connId, port });

    // 等待客户端建立数据通道（超时 10s）
    const dataChannel = await waitForDataChannel(client, connId, 10000).catch(() => null);
    if (!dataChannel) {
      externalConn.destroy();
      return;
    }

    // 双向管道
    externalConn.pipe(dataChannel);
    dataChannel.pipe(externalConn);
    externalConn.on('error', () => dataChannel.destroy());
    dataChannel.on('error', () => externalConn.destroy());
  });

  server.listen(port, () => {
    console.log(`[Relay/TCP] 中继服务器已启动，监听端口 ${port}`);
  });
  server.on('error', (err) => {
    console.error(`[Relay/TCP] 端口 ${port} 启动失败:`, err.message);
    tcpServers.delete(port);
  });
  tcpServers.set(port, server);
}

/**
 * 停止 TCP 中继服务器
 */
function stopTcpServer(port) {
  const server = tcpServers.get(port);
  if (server) {
    server.close();
    tcpServers.delete(port);
    console.log(`[Relay/TCP] 端口 ${port} 中继已停止`);
  }
}

// ==================== UDP 中继 ====================

/**
 * 启动 UDP 中继（UDP 包通过 TCP 控制通道转发给客户端）
 */
function startUdpRelay(port, clientToken) {
  if (udpSockets.has(port)) return;

  const socket = dgram.createSocket('udp4');

  socket.on('message', (msg, rinfo) => {
    const client = relayClients.get(clientToken);
    if (!client || !client.controlSocket || client.controlSocket.destroyed) return;

    // 封装成控制消息发给客户端
    sendControl(client.controlSocket, {
      type: 'UDP_PACKET',
      port,
      from: { address: rinfo.address, port: rinfo.port },
      data: msg.toString('base64'),
    });

    // 监听客户端回复（通过控制通道）
    if (!client.udpReplyListeners) client.udpReplyListeners = new Map();
    const key = `${rinfo.address}:${rinfo.port}`;
    client.udpReplyListeners.set(key, (replyData) => {
      socket.send(Buffer.from(replyData, 'base64'), rinfo.port, rinfo.address);
    });
  });

  socket.bind(port, () => {
    console.log(`[Relay/UDP] UDP 中继已启动，监听端口 ${port}`);
  });
  socket.on('error', (err) => {
    console.error(`[Relay/UDP] 端口 ${port} 启动失败:`, err.message);
    udpSockets.delete(port);
  });
  udpSockets.set(port, socket);
}

/**
 * 停止 UDP 中继
 */
function stopUdpSocket(port) {
  const socket = udpSockets.get(port);
  if (socket) {
    socket.close();
    udpSockets.delete(port);
    console.log(`[Relay/UDP] 端口 ${port} UDP 中继已停止`);
  }
}

// ==================== 控制通道处理 ====================

/** 向控制 socket 发送 JSON 控制消息（换行分隔） */
function sendControl(socket, msg) {
  if (!socket || socket.destroyed) return;
  try {
    socket.write(JSON.stringify(msg) + '\n');
  } catch (e) {
    // ignore
  }
}

/**
 * 等待客户端为 connId 建立数据通道
 * （客户端通过控制通道发送 DATA_CHAN 消息，携带 connId 和新 TCP 连接的端口）
 */
function waitForDataChannel(client, connId, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      client.pendingChannels && client.pendingChannels.delete(connId);
      reject(new Error('等待数据通道超时'));
    }, timeoutMs);

    if (!client.pendingChannels) client.pendingChannels = new Map();
    client.pendingChannels.set(connId, (socket) => {
      clearTimeout(timer);
      resolve(socket);
    });
  });
}

/**
 * 注册中继客户端连接（客户端发起 WebSocket/TCP 控制通道时调用）
 * @param {string} token - 客户端 token
 * @param {net.Socket} controlSocket - 控制通道 TCP socket
 * @returns {Promise<Object>} 客户端信息
 */
async function registerClient(token, controlSocket) {
  const row = await dbGet(
    'SELECT rc.*, u.id AS user_id FROM relay_clients rc JOIN users u ON rc.user_id = u.id WHERE rc.token = ?',
    [token]
  );
  if (!row) throw new Error('无效的客户端 token');

  // 更新 last_seen
  await dbRun('UPDATE relay_clients SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', [row.id]);

  const clientInfo = {
    id: row.id,
    userId: row.user_id,
    name: row.name,
    controlSocket,
    pendingChannels: new Map(),
    udpReplyListeners: new Map(),
    connectedAt: Date.now(),
  };

  relayClients.set(token, clientInfo);
  clientIdToToken.set(row.id, token);

  // 自动启动该客户端已有的 TCP/UDP 规则
  const rules = await dbAll(
    'SELECT * FROM relay_rules WHERE relay_client_id = ? AND enabled = 1',
    [row.id]
  );
  for (const rule of rules) {
    if (rule.protocol === 'tcp') startTcpRelayServer(rule.listen_port, token);
    if (rule.protocol === 'udp') startUdpRelay(rule.listen_port, token);
  }

  controlSocket.on('close', () => unregisterClient(token));
  controlSocket.on('error', () => unregisterClient(token));

  console.log(`[Relay] 客户端已连接: ${row.name || row.id} (用户 ${row.user_id})`);
  return clientInfo;
}

/**
 * 注销客户端（断开时调用）
 */
async function unregisterClient(token) {
  const client = relayClients.get(token);
  if (!client) return;

  // 停止该客户端的所有中继
  const rules = await dbAll(
    'SELECT listen_port, protocol FROM relay_rules WHERE relay_client_id = ? AND enabled = 1',
    [client.id]
  ).catch(() => []);
  for (const rule of rules) {
    if (rule.protocol === 'tcp') stopTcpServer(rule.listen_port);
    if (rule.protocol === 'udp') stopUdpSocket(rule.listen_port);
  }

  clientIdToToken.delete(client.id);
  relayClients.delete(token);
  console.log(`[Relay] 客户端已断开: ${client.name || client.id}`);
}

/**
 * 获取当前活跃中继状态快照（用于超管和状态 API）
 */
function getRelayStatus() {
  return {
    activeTcpPorts: [...tcpServers.keys()],
    activeUdpPorts: [...udpSockets.keys()],
    connectedClients: [...relayClients.values()].map(c => ({
      id: c.id,
      name: c.name,
      userId: c.userId,
      connectedAt: c.connectedAt,
    })),
  };
}

/**
 * 超管：获取所有转发规则（含中继客户端信息）
 */
function adminGetAllRules() {
  return dbAll(
    `SELECT rr.*, rc.name AS client_name, u.fingerprint AS user_fingerprint, u.display_name
     FROM relay_rules rr
     LEFT JOIN relay_clients rc ON rr.relay_client_id = rc.id
     JOIN users u ON rr.user_id = u.id
     ORDER BY rr.user_id, rr.created_at DESC`,
    []
  );
}

module.exports = {
  // 客户端管理
  createRelayClient,
  deleteRelayClient,
  getUserRelayClients,
  // 规则管理
  createRelayRule,
  deleteRelayRule,
  getUserRelayRules,
  // 连接管理
  registerClient,
  unregisterClient,
  sendControl,
  waitForDataChannel,
  // 状态
  getRelayStatus,
  adminGetAllRules,
  // 底层（供 server.js 控制通道端点使用）
  relayClients,
};
