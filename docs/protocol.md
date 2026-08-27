# 控制协议与数据面 wire 格式

> 本文是 `docs/rust-tunnel-design.md` §8/§9/§10 的可实现规格。实现见 `crates/tunnel-protocol`。
> 方向记号：`A→S` Agent 发往 Server；`S→A` Server 发往 Agent；`A↔S` 双向。

## 1. 传输载体

一个 Agent 与 Server 之间只有一条 QUIC Connection，其上有三类通道：

| 通道 | 承载 | 消息 |
|------|------|------|
| 控制流（一条 bidi stream，第一个打开） | 控制面消息 | HELLO/AUTH/PING/CONFIG_*/UDP_OPEN/UDP_CLOSE/STATS/HEALTH/ERROR |
| 数据流（每条连接一条 bidi stream） | TCP/HTTP 数据 | OPEN_TCP/OPEN_OK/OPEN_FAIL/CLOSE + 裸字节 |
| Datagram | UDP 载荷 | 见 §5 |

> **不在 QUIC 上重新发明 stream_id**：每条 TCP/HTTP 连接对应一条独立 QUIC bidi stream，用 stream 本身做多路复用（设计文档 §7）。

---

## 2. 帧格式（控制流 + 数据流首帧）

控制流上的每条消息、以及每条数据流的"首帧"，都使用下面的长度前缀帧：

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           length (u32 BE)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         message_type (u16 BE)  |          flags (u16 BE)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        request_id (u64 BE)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          payload (n bytes)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- `length`：`message_type + flags + request_id + payload` 的字节数（**不含**这 4 字节本身）。即 `length = 2 + 2 + 8 + payload.len()`。
- 所有多字节整数为 **network byte order / big-endian**。
- `payload`：控制面消息为 **UTF-8 JSON**；数据流"首帧"之后紧跟**裸字节**（不再有帧头）。
- `request_id`：请求-响应对（PING/PONG、CONFIG_UPDATE/CONFIG_ACK、OPEN_TCP/OPEN_OK 等）用同一 `request_id` 关联；单向通知可为 0。

**解码约束**（fuzz 目标，必须返回 `Err` 而非 panic）：
- `length` 超上限（默认 `MAX_FRAME = 4 MiB`）→ `Err(FRAME_TOO_LARGE)`。
- 流内字节不足 `length` → 等待或 `Err(TRUNCATED)`。
- 未知 `message_type` → `Err(UNKNOWN_MESSAGE)`（可选消息可忽略，见 §8）。

---

## 3. 消息目录

### 3.1 控制面消息（JSON payload）

| type | 名称 | 方向 | 说明 |
|------|------|------|------|
| 0x0001 | HELLO | A→S | 能力与版本 |
| 0x0002 | AUTH | A→S | 凭据认证 |
| 0x0003 | AUTH_OK | S→A | 认证成功 |
| 0x0004 | AUTH_FAIL | S→A | 认证失败 |
| 0x0010 | PING | A→S | 心跳 |
| 0x0011 | PONG | S→A | 心跳回包 |
| 0x0020 | CONFIG_SNAPSHOT | S→A | 全量配置 |
| 0x0021 | CONFIG_UPDATE | S→A | 增量配置 |
| 0x0022 | CONFIG_ACK | A→S | 配置确认 |
| 0x0023 | CONFIG_RESYNC | A→S | 请求全量 |
| 0x0040 | UDP_OPEN | S→A | 建 UDP 会话 |
| 0x0041 | UDP_CLOSE | A↔S | 关 UDP 会话 |
| 0x0050 | STATS | A→S | 流量统计上报 |
| 0x0051 | HEALTH | A→S | 状态上报 |
| 0x0060 | ERROR | A↔S | 错误 |

### 3.2 数据流消息（JSON 首帧）

| type | 名称 | 方向 | 说明 |
|------|------|------|------|
| 0x0030 | OPEN_TCP | S→A | 打开一条转发（正向首帧） |
| 0x0031 | OPEN_OK | A→S | 目标连接成功（反向首帧） |
| 0x0032 | OPEN_FAIL | A→S | 目标连接失败（反向首帧） |
| 0x0033 | CLOSE | A↔S | 关闭（终止帧，可选） |

---

## 4. 各消息 payload 定义

> 字段均为 JSON 对象。字符串 ID 为 UUID（`"018f…"`）。

### HELLO（A→S）
```json
{
  "protocol_version": { "major": 1, "minor": 0 },
  "agent_version": "0.1.0",
  "capabilities": { "tcp": true, "udp": true, "http": true, "websocket": true, "quic": true }
}
```

### AUTH（A→S）
```json
{
  "node_id": "018f…",          // 可选；缺省时 Server 由 credential 反查 node
  "credential": "<token>"      // token 模式；mTLS 模式下可省略（客户端证书已证明身份）
}
```
- Server 对 `credential` 做 hash 后比对 `credentials.secret_hash`，并检查 `revoked_at`/`expires_at` 与 node `disabled`。
- 认证成功后 Server 写 `last_used_at`、更新 node 上线状态。

### AUTH_OK（S→A）
```json
{
  "node_id": "018f…",
  "config_version": 184,
  "server_version": "0.1.0",
  "server_time": "2026-08-27T12:00:00Z"
}
```

### AUTH_FAIL（S→A）
```json
{ "code": "AUTH_FAILED", "message": "invalid credential" }
```

### PING / PONG
```json
{ "ts": 1720000000000 }   // 毫秒时间戳（PONG 回带，用于算 rtt）
```

### CONFIG_SNAPSHOT（S→A）— 全量
```json
{
  "config_version": 184,
  "routes": [
    {
      "id": "018f…", "name": "ssh", "type": "tcp",
      "enabled": true, "target_host": "192.168.1.100", "target_port": 22
    }
  ],
  "acl": [
    { "action": "allow", "source_cidr": "10.0.0.0/8" }
  ],
  "limits": { "max_connections": 10000, "max_bandwidth": null }
}
```

### CONFIG_UPDATE（S→A）— 增量
```json
{
  "config_version": 185,
  "routes": {
    "added":   [ { "id": "…", "name": "web", "type": "http", "target_host": "…", "target_port": 3000 } ],
    "updated": [ { "id": "…", "target_port": 3001 } ],
    "removed": [ "018f…" ]
  },
  "limits": { "max_connections": 10000 }
}
```

### CONFIG_ACK（A→S）
```json
{ "config_version": 185, "applied": true, "error": null }
```
失败时：`{ "config_version": 185, "applied": false, "error": { "code": "CONFIG_INVALID", "message": "…" } }`

### CONFIG_RESYNC（A→S）
```json
{ "last_applied_version": 183 }
```
Server 收到后回复 `CONFIG_SNAPSHOT`。

### UDP_OPEN（S→A）
```json
{ "route_id": "018f…", "udp_session_id": 12345, "client_addr": "1.2.3.4:5678" }
```

### UDP_CLOSE（A↔S）
```json
{ "udp_session_id": 12345 }
```

### STATS（A→S，周期上报）
```json
{ "rx_bytes": 123456, "tx_bytes": 654321, "active_streams": 12, "errors": 0 }
```

### HEALTH（A→S，周期上报）
```json
{ "applied_config_version": 184, "status": "ok", "uptime_seconds": 3600 }
```

### ERROR（A↔S）
```json
{ "code": "PROTOCOL_ERROR", "message": "…", "request_id": 0 }
```

### OPEN_TCP（S→A，数据流正向首帧）
```json
{
  "route_id": "018f…",
  "target_host": "192.168.1.100",
  "target_port": 22,
  "client_addr": "1.2.3.4:45678"    // 可选，用于日志/透明源 IP（PROXY v2 后续）
}
```
> HTTP 路由也复用 `OPEN_TCP`：Server 已在 HTTP 层完成 Host 路由与 header 注入，Agent 只需连 `target_host:target_port` 并透传后续字节，无需解析 HTTP。

### OPEN_OK（A→S，数据流反向首帧）
```json
{ "remote_addr": "192.168.1.100:22" }
```

### OPEN_FAIL（A→S，数据流反向首帧）
```json
{ "code": "TARGET_UNREACHABLE", "message": "connection refused" }
```

### CLOSE（A↔S，终止帧）
```json
{ "code": "EOF" }   // 可选，描述关闭原因
```

---

## 5. UDP Datagram 格式

每个 UDP 包封装进一个 QUIC Datagram：

```text
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          flags (u16 BE)        |      udp_session_id (u64 BE)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      UDP payload (n bytes)                     |
```

- `flags`：bit0 = `fragment`（v1 恒为 0，分片留待后续）；其余保留为 0。
- `udp_session_id`：由 Server 在 `UDP_OPEN` 中分配。
- **大包**：超过 `max_datagram_size`（默认 1200，受 PMTU 约束）的 UDP payload **丢弃并计数**（v1 不做分片/重组）。

---

## 6. 连接生命周期与时序

### 6.1 Agent 上线（认证）
```text
Agent                              Server
  |  QUIC connect                    |
  |  open control stream             |
  |  HELLO ────────────────────────> |
  |  AUTH  ────────────────────────> | 校验凭据 → 更新 node 状态
  |  <────────────────────── AUTH_OK | 携带 config_version
  |  <────────────── CONFIG_SNAPSHOT | 下发全量配置
  |  CONFIG_ACK ───────────────────> |
```

### 6.2 心跳与超时
- 默认 interval 15s / timeout 45s（设计文档 §35）。
- 45s 未收到 PONG → 判定离线，关连接；Agent 进入重连（§34）。

### 6.3 TCP 转发（Server 收到公网 TCP 连接）
```text
Public client      Server                    Agent            Target
  |  TCP SYN         |                        |                 |
  |                  | 查 listen→route→node    |                 |
  |                  | 开 bidi stream          |                 |
  |                  | OPEN_TCP ────────────> | 连 target       |
  |                  |                        |───────────────> |
  |  <──────────────>|  <── 裸字节双向 ──────> | <─────────────> |
  |                  | <────────────── OPEN_OK |（目标连上才回，Server 收到前先缓冲客户端首段数据）
```
- Server 在收到 `OPEN_OK` 前，先缓冲客户端到达的字节（有上限），收到 `OPEN_OK` 后开始转发；收到 `OPEN_FAIL` 则关闭并回错误。

### 6.4 配置热更新
```text
Web → API → DB(commit) → Config Manager(version++) → Session Manager
  |  CONFIG_UPDATE {config_version: N} ──────────────> Agent
  |  校验 → 应用
  |  <──────────────────────────── CONFIG_ACK {N, applied}
```
- Agent 发现 `N > last_applied + 1` → 发 `CONFIG_RESYNC`，Server 回 `CONFIG_SNAPSHOT`。

---

## 7. Stream 状态机

```text
OPEN ──> CONNECTING ──> OPEN ──> HALF_CLOSED ──> CLOSED
                              └──> FAILED（任一阶段异常）
```
- `OPEN`：Server 已开流、发 OPEN_TCP。
- `CONNECTING`：Agent 正在连目标。
- `OPEN`（第二个）：OPEN_OK 收到，双向转发中。
- `HALF_CLOSED`：一端 FIN，另一端仍可写（支持 half-close，§109）。
- `FAILED`：OPEN_FAIL / 传输错误 / 超时。

---

## 8. 错误码（协议层）

| 错误码 | 语义 |
|--------|------|
| AUTH_FAILED | 凭据无效/吊销/过期 |
| NODE_DISABLED | node 被禁用 |
| ROUTE_NOT_FOUND | 路由不存在 |
| ROUTE_DISABLED | 路由被禁用 |
| TARGET_UNREACHABLE | 目标不可达 |
| TARGET_TIMEOUT | 目标连接超时 |
| TARGET_DENIED | 目标被 ACL 拒绝 |
| RESOURCE_LIMIT | 超过连接/流/带宽上限 |
| CONFIG_INVALID | 配置非法 |
| PROTOCOL_ERROR | 协议解析错误 |
| INTERNAL_ERROR | 内部错误 |

---

## 9. 版本兼容

- `protocol_version.major` 不兼容；`minor` 向后兼容（设计文档 §89）。
- 未知消息：`optional` 忽略，`required` 关闭连接。
- Server 配置 `min_agent_version`，Agent 太旧 → `upgrade_required`。
