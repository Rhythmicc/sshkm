#!/usr/bin/env node
/**
 * relay-client.js — sshkm NAT 穿透中继客户端
 *
 * 使用方式：
 *   node relay-client.js --server http://your-server:3000 --token <TOKEN>
 *
 * 工作流程：
 *
 *   ┌──────────────────────────────────────────────────────────────────────┐
 *   │  控制通道（持久 HTTP 长连接，客户端主动外连，NAT 友好）              │
 *   │                                                                      │
 *   │  客户端  ──GET /relay/connect──►  服务端                            │
 *   │          ◄── AUTH_OK ──                                             │
 *   │          ◄── PING / NEW_CONN ──                                      │
 *   │          ── PONG ──►                                                 │
 *   └──────────────────────────────────────────────────────────────────────┘
 *
 *   当外部用户连接到服务端分配的 listen_port 时：
 *
 *   外部用户 ──TCP──► 服务端 listen_port
 *                        │
 *                        ▼
 *   服务端 ──NEW_CONN {connId}──► 客户端（通过控制通道）
 *                        │
 *                        ▼
 *   客户端  ──GET /relay/data?connId=xxx&token=yyy──► 服务端（新出站连接）
 *                        │
 *                 服务端将 data socket ↔ 外部连接 对接
 *                        │
 *                        ▼
 *   客户端  ──pipe──► 本地服务（localhost:targetPort）
 *
 *   最终效果：外部用户 ↔ 服务端 listen_port ↔ 数据通道 ↔ 本地 targetPort
 *
 * 在网页控制台中：
 *   1. 登录 → 创建中继客户端 → 复制 token
 *   2. 为该客户端添加 TCP/UDP 规则，设置目标端口（如 22）
 *   3. 在内网机器上运行本客户端：
 *      node relay-client.js --server http://server:3000 --token <TOKEN>
 */

'use strict';

const net = require('net');
const http = require('http');
const https = require('https');
const { URL } = require('url');

// ==================== 参数解析 ====================

const args = process.argv.slice(2);
function getArg(name) {
  const i = args.indexOf(name);
  return i !== -1 ? args[i + 1] : null;
}

const SERVER_URL = getArg('--server') || process.env.RELAY_SERVER || 'http://localhost:3000';
const TOKEN = getArg('--token') || process.env.RELAY_TOKEN;
const RECONNECT_DELAY_MS = parseInt(getArg('--reconnect') || '5000', 10);
const PING_INTERVAL_MS = parseInt(getArg('--ping') || '20000', 10);
const VERBOSE = args.includes('--verbose');

if (!TOKEN) {
  console.error('错误：缺少 --token 参数');
  console.error('用法: node relay-client.js --server http://server:3000 --token <TOKEN>');
  process.exit(1);
}

const baseUrl = new URL(SERVER_URL);
const httpLib = baseUrl.protocol === 'https:' ? https : http;

// ==================== 连接管理 ====================

let controlSocket = null;
let pingTimer = null;
let reconnectTimer = null;
let shuttingDown = false;
let buf = '';

function log(...args) {
  console.log(`[${new Date().toLocaleTimeString()}]`, ...args);
}
function debug(...args) {
  if (VERBOSE) console.log(`[DEBUG]`, ...args);
}

/**
 * 建立并保持控制通道连接
 */
function connectControl() {
  if (shuttingDown) return;

  log(`正在连接到服务端 ${SERVER_URL} ...`);

  const options = {
    hostname: baseUrl.hostname,
    port: baseUrl.port || (baseUrl.protocol === 'https:' ? 443 : 80),
    path: '/relay/connect',
    method: 'GET',
    headers: {
      'Connection': 'keep-alive',
    },
  };

  const req = httpLib.request(options, (res) => {
    if (res.statusCode !== 200) {
      log(`控制通道响应异常 HTTP ${res.statusCode}，将在 ${RECONNECT_DELAY_MS}ms 后重试`);
      scheduleReconnect();
      return;
    }

    controlSocket = res.socket;
    controlSocket.setTimeout(0);
    controlSocket.setKeepAlive(true, 15000);
    buf = '';

    // 发送鉴权消息
    sendMsg({ type: 'AUTH', token: TOKEN });

    res.on('data', (chunk) => {
      buf += chunk.toString();
      const lines = buf.split('\n');
      buf = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          handleControlMessage(JSON.parse(line));
        } catch (e) {
          debug('解析控制消息失败:', line);
        }
      }
    });

    res.on('end', () => {
      log('控制通道关闭，将重新连接...');
      cleanup();
      scheduleReconnect();
    });
  });

  req.on('error', (err) => {
    log(`控制通道连接错误: ${err.message}，将在 ${RECONNECT_DELAY_MS}ms 后重试`);
    cleanup();
    scheduleReconnect();
  });

  req.end();
}

/**
 * 处理来自服务端的控制消息
 */
function handleControlMessage(msg) {
  debug('收到控制消息:', JSON.stringify(msg));

  switch (msg.type) {
    case 'AUTH_OK':
      log('✓ 鉴权成功，中继已激活');
      startPing();
      break;

    case 'AUTH_FAIL':
      log(`✗ 鉴权失败: ${msg.reason}`);
      log('请检查 token 是否正确');
      shuttingDown = true; // 不重试
      cleanup();
      break;

    case 'PONG':
      debug(`PONG 延迟: ${Date.now() - msg.ts}ms`);
      break;

    case 'NEW_CONN':
      // 服务端有新的外部连接进来，我们需要建立数据通道
      handleNewConn(msg.connId, msg.listenPort || msg.port, msg.targetPort, msg.targetHost);
      break;

    default:
      debug('未知消息类型:', msg.type);
  }
}

/**
 * 向服务端发送控制消息
 */
function sendMsg(msg) {
  if (!controlSocket || controlSocket.destroyed) return;
  try {
    controlSocket.write(JSON.stringify(msg) + '\n');
  } catch (e) {
    debug('发送控制消息失败:', e.message);
  }
}

/**
 * 启动 PING 心跳
 */
function startPing() {
  stopPing();
  pingTimer = setInterval(() => {
    sendMsg({ type: 'PING', ts: Date.now() });
  }, PING_INTERVAL_MS);
}

function stopPing() {
  if (pingTimer) { clearInterval(pingTimer); pingTimer = null; }
}

function cleanup() {
  stopPing();
  controlSocket = null;
}

function scheduleReconnect() {
  if (shuttingDown || reconnectTimer) return;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connectControl();
  }, RECONNECT_DELAY_MS);
}

// ==================== 数据通道 ====================

/**
 * 处理 NEW_CONN：建立数据通道并接入本地服务
 * @param {string} connId       - 服务端分配的连接 ID
 * @param {number} listenPort   - 服务端监听的端口
 * @param {number} [ruleTarget] - 服务端规则里配置的目标端口（优先使用）
 * @param {string} [ruleHost]   - 服务端规则里配置的目标主机（优先使用）
 */
function handleNewConn(connId, listenPort, ruleTarget, ruleHost) {
  log(`新连接请求 connId=${connId} 来自端口 ${listenPort}，正在建立数据通道...`);

  // 1. 向服务端建立数据通道连接
  const dataOptions = {
    hostname: baseUrl.hostname,
    port: baseUrl.port || (baseUrl.protocol === 'https:' ? 443 : 80),
    path: `/relay/data?connId=${encodeURIComponent(connId)}&token=${encodeURIComponent(TOKEN)}`,
    method: 'GET',
    headers: { 'Connection': 'keep-alive' },
  };

  const dataReq = httpLib.request(dataOptions, (dataRes) => {
    if (dataRes.statusCode !== 200) {
      log(`数据通道建立失败 HTTP ${dataRes.statusCode}`);
      return;
    }

    const dataSocket = dataRes.socket;
    dataSocket.setTimeout(0);

    // 2. 连接到本地目标服务
    // 优先级：服务端规则里的 targetPort > 命令行 --map > 命令行 --default-port > 22
    const targetPort = ruleTarget || getTargetPort(listenPort);
    const targetHost = ruleHost || getArg('--target-host') || 'localhost';

    log(`  数据通道就绪，正在连接本地服务 ${targetHost}:${targetPort} ...`);

    const localConn = net.createConnection(targetPort, targetHost);

    localConn.once('connect', () => {
      log(`  ✓ 已接通 ${targetHost}:${targetPort} ↔ connId=${connId}`);

      // 在 HTTP 响应开始后，socket 已经不再有 HTTP 帧，可以直接当 TCP 管道
      // 注意：需要将 dataRes 中已缓冲的数据先 pipe 给 localConn
      dataRes.pipe(localConn);
      localConn.pipe(dataSocket);

      localConn.on('error', () => dataSocket.destroy());
      dataSocket.on('error', () => localConn.destroy());
      localConn.on('close', () => dataSocket.destroy());
      dataSocket.on('close', () => localConn.destroy());
    });

    localConn.on('error', (err) => {
      log(`  ✗ 连接本地服务失败: ${err.message}`);
      dataSocket.destroy();
    });
  });

  dataReq.on('error', (err) => {
    log(`数据通道连接失败: ${err.message}`);
  });

  dataReq.end();
}

// ==================== 端口映射 ====================

/**
 * 根据服务端监听端口找到本地目标端口。
 *
 * 优先级：
 *  1. 命令行 --map 参数：--map 6001:22 --map 6002:80
 *  2. 命令行 --default-port 参数
 *  3. 默认 22
 */
const portMap = new Map();

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--map' && args[i + 1]) {
    const [listenPort, targetPort] = args[i + 1].split(':').map(Number);
    if (listenPort && targetPort) {
      portMap.set(listenPort, targetPort);
    }
    i++;
  }
}

const defaultTargetPort = parseInt(getArg('--default-port') || '22', 10);

function getTargetPort(listenPort) {
  return portMap.get(listenPort) || defaultTargetPort;
}

// ==================== 启动 ====================

log('sshkm 中继客户端启动');
log(`服务端: ${SERVER_URL}`);
log(`默认目标端口: ${defaultTargetPort}`);
if (portMap.size > 0) {
  log('端口映射:');
  for (const [lp, tp] of portMap) {
    log(`  服务端 :${lp}  →  本地 :${tp}`);
  }
}
log('---');

connectControl();

process.on('SIGINT', () => {
  log('正在关闭...');
  shuttingDown = true;
  cleanup();
  process.exit(0);
});

process.on('SIGTERM', () => {
  shuttingDown = true;
  cleanup();
  process.exit(0);
});
