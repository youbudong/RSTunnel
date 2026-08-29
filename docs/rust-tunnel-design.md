# Rust Tunnel：完整产品级开发文档

**文档版本：** 1.1（修订版）
**目标：** 构建一个可自托管、可生产部署的 Cloudflare Tunnel / FRP 类内网穿透平台。
**核心组件：** Tunnel Server、Tunnel Agent、Web 管理后台、REST API、WebSocket、数据库、QUIC/TLS。
**原则：** Web 是配置中心；配置持久化到数据库；Server 动态下发配置；Agent 主动出站连接；不依赖内网端口映射。

> **本版修订说明（v1.0 → v1.1）**
>
> 1. 清理了正文中残留的引用标记与重复段落（§5、§7、§32）。
> 2. 重写 §19/§20：schema 改为 SQLite / PostgreSQL 都可移植的类型；补上缺失的 `domains`、`certificates`、`traffic_stats` 表；`credentials` 补 `type`；`acl_rules` 扩展匹配字段；核心表预留 `tenant_id`。
> 3. 统一 `config_version` 语义：改为**每个 Node 一个全局快照版本**（存 `nodes` 表），不再挂在 `routes` 上；补上协议里的 `CONFIG_RESYNC`。
> 4. 澄清协议消息归属：控制流 vs 数据流 vs Datagram 各承载哪些消息。
> 5. 统一端口/API 暴露策略：公网 HTTPS 入口、回环 internal 入口、Docker 端口映射三者对齐，消除矛盾。
> 6. 统一术语（Node / Agent / Session / Route），并新增术语表（§17.1）。
> 7. 补充安全遗漏：UDP 反射/源地址欺骗、注册信任链、IPv6、HA 下 UDP 负载均衡。
> 8. 若干小修正：TOML 与导入导出格式区分、UDP 大包分片、依赖清单、`web/` 目录归属。

---

# 1. 项目目标

## 1.1 产品定位

系统允许用户在一台具有公网 IP 的服务器上运行 Tunnel Server，在 NAT/防火墙后的机器运行 Tunnel Agent。

Agent 主动建立到 Server 的安全长连接：

```text
Internet
   |
   +----------------------+
   |                      |
   v                      v
HTTP/HTTPS              TCP/UDP
   |                      |
   +----------+-----------+
              |
       Tunnel Server
              |
          QUIC/TLS
              |
          Tunnel Agent
              |
      +-------+-------+
      |       |       |
     HTTP    SSH     TCP
```

公网用户访问 Server 的公网地址后，Server 根据路由把连接转交给指定 Agent，再由 Agent 访问内网目标。

## 1.2 核心能力

必须支持：

- 多 Agent
- 多 Tunnel
- TCP
- UDP
- HTTP
- HTTPS
- WebSocket
- QUIC
- TLS 1.3
- Agent 自动注册/认证
- Agent 自动重连
- Tunnel 热更新
- Web 配置
- REST API
- WebSocket 实时状态
- 用户认证
- RBAC
- ACL
- 审计日志
- 连接限制
- 流量统计
- 运行日志
- 健康检查
- Docker 部署
- systemd 部署
- SQLite
- PostgreSQL
- 配置版本控制
- 多 Server 架构预留
- Agent 多 Server 故障转移

---

# 2. 非目标

第一版不要求：

- 自己实现 QUIC
- 自己实现 TLS
- 自己实现 HTTP/2
- 自己实现 HTTP/3
- 自己实现密码学算法
- 修改 Linux 内核网络栈
- 做透明代理/VPN
- 做完整 SD-WAN
- 做流量审计 DPI

优先使用成熟 Rust crate。

---

# 3. 总体架构

```text
                         Internet
                            |
              +-------------+-------------+
              |                           |
          HTTP/HTTPS                   TCP/UDP
              |                           |
              +-------------+-------------+
                            |
                    +-------v-------+
                    | Tunnel Server |
                    |               |
                    | HTTP Gateway  |
                    | TCP Listener  |
                    | UDP Gateway   |
                    | Router        |
                    | Auth          |
                    | API           |
                    | Config        |
                    | Session       |
                    +-------+-------+
                            |
                       QUIC / TLS
                            |
             +--------------+--------------+
             |              |              |
        +----v----+    +----v----+    +----v----+
        | Agent A |    | Agent B |    | Agent C |
        +----+----+    +---------+    +---------+
             |
      +------+------+------+
      |      |      |      |
     HTTP   SSH    TCP    UDP
      |      |      |      |
   LAN services / localhost
```

---

# 4. 组件

## 4.1 Server

职责：

- 接受 Agent QUIC 连接
- Agent 身份认证
- Session 管理
- Route 管理
- TCP Listener
- UDP Listener
- HTTP/HTTPS Gateway
- HTTP Host 路由
- TLS 证书管理
- API
- WebSocket
- 数据库
- 用户认证
- RBAC
- ACL
- 统计
- 日志
- 审计
- 配置热更新

## 4.2 Agent

职责：

- 主动连接 Server
- 身份认证
- 心跳
- 自动重连
- 接收配置
- 建立到目标服务的连接
- TCP 转发
- UDP 转发
- HTTP 模式下的目标访问
- 本地 ACL
- 流量统计
- 状态上报
- 优雅关闭

## 4.3 Web

职责：

- 登录
- Dashboard
- Node 管理
- Tunnel 管理
- Route 管理
- Domain 管理
- Certificate 管理
- User 管理
- Role 管理
- ACL
- 日志
- 审计
- Metrics
- Server 设置

## 4.4 Database

数据库保存控制面状态，不保存普通 Tunnel 数据。

---

# 5. 技术栈

## Server / Agent

```text
Rust
Tokio
Quinn
Rustls
Axum
Serde
SQLx
Tracing
Tracing-subscriber
UUID
Time
Bytes
Futures-util
Anyhow / thiserror
```

推荐：

```text
QUIC      -> quinn
Async     -> tokio
HTTP API  -> axum
DB        -> sqlx
TLS       -> rustls
Config    -> serde + toml
Logs      -> tracing
Metrics   -> prometheus
```

QUIC 本身提供连接、独立 Stream、流控和多路复用；Quinn 是 Rust 的 QUIC 实现并直接提供 Tokio 异步 API，因此 Tunnel 不应重复实现自己的 TCP 多路复用层。传输层直接采用 QUIC/TLS 1.3（QUIC 已内置 TLS 1.3 加密与握手），不使用自研协议或自研加密。

---

# 6. Cargo Workspace

```text
rust-tunnel/
├── Cargo.toml
├── crates/
│   ├── protocol/      # 协议编解码（纯 Rust，无 IO）
│   ├── config/        # 配置结构与校验
│   ├── core/          # 核心抽象（transport / route / connector trait）
│   ├── auth/          # 认证与凭据
│   ├── database/      # SQLx 数据访问层
│   ├── metrics/       # 指标定义
│   └── common/        # 错误、日志、工具
├── server/            # Rust 二进制：tunnel-server
├── agent/             # Rust 二进制：tunnel-agent
├── web/               # TypeScript 前端（独立于 Cargo，见 §65）
├── migrations/        # SQLx 迁移脚本
├── deploy/
│   ├── docker/
│   └── systemd/
├── docs/
└── tests/
```

建议依赖方向：

```text
protocol
    ↓
core
    ↓
server / agent
```

Web 通过 REST API 与 Server 通信。`web/` 是前端工程（TS），**不是** Cargo crate，不参与 workspace 构建。

---

# 7. Tunnel Session

一个 Agent 与 Server 建立一个 QUIC Connection。

```text
QUIC Connection
|
+-- control stream
|
+-- bidirectional stream
|      +-- TCP connection 1
|
+-- bidirectional stream
|      +-- TCP connection 2
|
+-- bidirectional stream
|      +-- HTTP request
|
+-- datagrams
       +-- UDP packets
```

不要自己在 QUIC 之上重新定义 `stream_id` 来模拟 TCP multiplexing。QUIC Stream 本身就是独立的数据通道。Quinn 的 Connection 可以创建和管理多个 Stream，并支持 QUIC Datagram（用于 UDP 载荷）。

---

# 8. 控制协议

控制流（control stream）使用长度前缀二进制消息。

推荐：

```text
u32 length
u16 message_type
u16 flags
u64 request_id
payload
```

全部采用 network byte order / big endian。

## 8.1 Message Type

```text
0x0001 HELLO
0x0002 AUTH
0x0003 AUTH_OK
0x0004 AUTH_FAIL

0x0010 PING
0x0011 PONG

0x0020 CONFIG_SNAPSHOT
0x0021 CONFIG_UPDATE
0x0022 CONFIG_ACK
0x0023 CONFIG_RESYNC

0x0030 OPEN_TCP
0x0031 OPEN_OK
0x0032 OPEN_FAIL
0x0033 CLOSE

0x0040 UDP_OPEN
0x0041 UDP_CLOSE

0x0050 STATS
0x0051 HEALTH

0x0060 ERROR
```

## 8.2 消息归属（控制流 / 数据流 / Datagram）

- **控制流（一条 bidi stream）**：`HELLO`、`AUTH`、`AUTH_OK`、`AUTH_FAIL`、`PING`、`PONG`、`CONFIG_SNAPSHOT`、`CONFIG_UPDATE`、`CONFIG_ACK`、`CONFIG_RESYNC`、`UDP_OPEN`、`UDP_CLOSE`、`STATS`、`HEALTH`、`ERROR`。
- **数据流（每个连接一条 bidi stream）**：Server 打开一条新的 bidi stream 后，正向首帧是 `OPEN_TCP`（携带 route_id 与目标元数据），随后是裸 TCP 字节；Agent 侧反向首帧是 `OPEN_OK` 或 `OPEN_FAIL`（随后是裸字节）。`CLOSE` 可作为任一方向的终止帧。**不把 `OPEN_*` 放到控制流上，从而避免重新引入 stream_id。**
- **Datagram（UDP 载荷）**：每个 datagram 带一个短头部（`u16 flags` + `u64 udp_session_id`）+ UDP payload；`UDP_OPEN`/`UDP_CLOSE` 在控制流上管理会话生命周期。UDP 会话需要 session_id 是正常的（UDP 无 stream 概念，不违反 §7 的规则）。

---

# 9. Agent 连接生命周期

```text
Agent
  |
  | QUIC connect
  v
Server
  |
  | HELLO
  v
Server
  |
  | challenge / authentication
  v
Agent
  |
  | AUTH
  v
Server
  |
  | AUTH_OK
  v
Session established
```

认证成功后：

```text
CONFIG_SNAPSHOT
```

Server 下发 Agent 当前有效配置。

之后配置改变：

```text
CONFIG_UPDATE
```

Agent 返回：

```text
CONFIG_ACK
```

---

# 10. 配置版本

**配置版本是每个 Node 一个的全局快照版本**（存于 `nodes.config_version`，见 §20），表示该 Node 当前生效配置的快照号。任何影响该 Node 的 Route/ACL/Domain 变更都会令其 `config_version += 1`。

```text
Node config_version = 184
```

Server：

```text
desired version 184
```

Agent：

```text
applied version 183
```

Server 下发：

```text
CONFIG_UPDATE version=184
```

Agent：

```text
CONFIG_ACK version=184
```

如果 Agent 发现版本不连续：

```text
183 -> 190
```

则请求：

```text
CONFIG_RESYNC
```

重新获取完整 Snapshot。

---

# 11. Route 模型

Route 是系统最重要的数据模型之一（用户理解的"一条 Tunnel"在数据模型与 API 中统一叫 **Route**）。

```text
Route
├── id
├── name
├── type
├── enabled
├── node_id
├── listen
├── target
├── domain
├── tls
├── acl
├── limits
└── created_at
```

类型：

```text
tcp
udp
http
https
```

---

# 12. TCP Route

例：

```text
公网:
1.2.3.4:2222

Agent:
192.168.1.100:22
```

流程：

```text
Internet client
       |
       | TCP
       v
Server :2222
       |
       | open QUIC stream
       v
Agent
       |
       | TCP
       v
192.168.1.100:22
```

数据双向复制。

---

# 13. UDP Route

UDP 不建立传统 TCP stream。

模型：

```text
UDP Datagram
      |
      v
Server
      |
      v
QUIC Datagram
      |
      v
Agent
      |
      v
LAN UDP target
```

需要处理：

- source address
- destination address
- idle timeout
- session expiration
- packet size
- rate limit
- packet loss

UDP Route 应支持：

```text
max_datagram_size
idle_timeout
max_clients
rate_limit
```

> **注意（UDP 大包）**：QUIC Datagram 受路径 MTU 限制（通常 ~1200 字节可用）。超过该阈值的 UDP 包需要在数据面做分片/重组（datagram 头加 fragment 序号），或对大包直接丢弃并按策略计数。第一版至少要实现"超大包判定 + 明确报错/丢弃"，避免静默截断。

---

# 14. HTTP Route

HTTP 路由：

```text
Host:
app.example.com

Target:
192.168.1.100:3000
```

Server：

```text
HTTP Request
      |
      v
Host Router
      |
      v
Route
      |
      v
Agent
      |
      v
Target
```

Server 可以终止 TLS：

```text
Browser
  |
 HTTPS
  |
  v
Server
  |
 HTTP
  |
  v
Agent
```

也可以做 TLS passthrough。

---

# 15. HTTPS / TLS

支持两种模式：

## TLS Termination

```text
Client
  |
HTTPS
  |
Server
  |
HTTP/1.1
  |
Agent
  |
LAN
```

Server 管理证书。

## TLS Passthrough

```text
Client
  |
TLS
  |
Server
  |
TLS
  |
Agent
```

Server 仅根据 SNI 路由。

---

# 16. WebSocket

HTTP Tunnel 必须支持：

```text
Connection: Upgrade
Upgrade: websocket
```

WebSocket 数据在 Tunnel Stream 中双向转发。

---

# 17. Node

Node 是 Agent 的**逻辑身份**（注册实体）：管理员在 Web 上创建一个 Node 并为其生成凭据，随后某台机器上的 Agent 进程持该凭据连接上线。

字段：

```text
id
name
description
status
hostname
platform
architecture
agent_version
last_seen_at
connected_at
remote_addr
config_version
applied_config_version
config_status
created_at
updated_at
```

状态：

```text
pending
online
offline
disabled
```

## 17.1 术语对照

| 术语 | 含义 |
|------|------|
| **Node** | 逻辑身份（注册实体，拥有 credential / config / route） |
| **Agent** | 运行在目标机器上的进程，持有一个 Node 的凭据 |
| **Session** | Agent 与 Server 之间的一条 QUIC 连接（一个 Node 可先后有多个 Session） |
| **Route** | 数据面转发规则（即用户理解的"一条 Tunnel"）；API/数据模型统一用 Route |

"Tunnel Server / Tunnel Agent" 是产品组件名，保留；用户可见的"隧道"在数据模型与接口中一律叫 **Route**。

---

# 18. Credential

Agent 不直接使用用户密码。

Credential：

```text
id
node_id
type
secret_hash
created_at
expires_at
revoked_at
last_used_at
```

`type` 支持：

```text
token
mTLS certificate
```

Token 只在创建时完整显示一次。

数据库保存 hash。

---

# 19. 数据库

默认：

```text
SQLite
```

生产：

```text
PostgreSQL
```

使用 SQLx。

**可移植性约定**：§20 的 schema 统一使用可在 SQLite 与 PostgreSQL 上直接运行的可移植类型——主键/外键用 `TEXT` 存 UUID 字符串（应用层用 `uuid` crate 生成）；时间戳用 `TEXT` 存 RFC3339 / ISO-8601 UTC；布尔用 `BOOLEAN`（SQLite 下由 SQLx 映射为 0/1）；JSON 用 `TEXT` 存 JSON 字符串。若部署 PostgreSQL 且希望用原生 `UUID`/`TIMESTAMPTZ`/`JSONB`，需要单独维护一套 PG 专属迁移，v1 不强制。

---

# 20. 数据库 Schema

> 下列 DDL 为**可移植版本**（SQLite / PostgreSQL 通用）。主键统一 `TEXT`（UUID 字符串）。

## users

```sql
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    username TEXT NOT NULL UNIQUE,
    email TEXT UNIQUE,
    password_hash TEXT NOT NULL,
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
```

## roles

```sql
CREATE TABLE roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT
);
```

## user_roles

```sql
CREATE TABLE user_roles (
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    PRIMARY KEY (user_id, role_id)
);
```

## nodes

```sql
CREATE TABLE nodes (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    status TEXT NOT NULL,
    hostname TEXT,
    platform TEXT,
    architecture TEXT,
    agent_version TEXT,
    remote_addr TEXT,
    last_seen_at TEXT,
    connected_at TEXT,
    config_version BIGINT NOT NULL DEFAULT 0,
    applied_config_version BIGINT NOT NULL DEFAULT 0,
    config_status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
```

## credentials

```sql
CREATE TABLE credentials (
    id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL,
    type TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT,
    last_used_at TEXT,
    created_at TEXT NOT NULL
);
```

## routes

```sql
CREATE TABLE routes (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    name TEXT NOT NULL,
    node_id TEXT NOT NULL,
    type TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    listen_host TEXT,
    listen_port INTEGER,
    hostname TEXT,
    target_host TEXT NOT NULL,
    target_port INTEGER NOT NULL,
    tls_mode TEXT,
    status TEXT NOT NULL DEFAULT 'draft',
    limits TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
```

## acl_rules

```sql
CREATE TABLE acl_rules (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    route_id TEXT,
    action TEXT NOT NULL,
    source_cidr TEXT,
    source_port INTEGER,
    target_host TEXT,
    target_port INTEGER,
    created_at TEXT NOT NULL
);
```

## domains

```sql
CREATE TABLE domains (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    hostname TEXT NOT NULL,
    route_id TEXT,
    tls_mode TEXT,
    certificate_id TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
```

## certificates

```sql
CREATE TABLE certificates (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    name TEXT NOT NULL,
    hostnames TEXT NOT NULL,
    certificate TEXT NOT NULL,
    private_key_encrypted TEXT,
    expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
```

## traffic_stats

```sql
CREATE TABLE traffic_stats (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    node_id TEXT,
    route_id TEXT,
    window_start TEXT NOT NULL,
    window_seconds INTEGER NOT NULL,
    rx_bytes BIGINT NOT NULL DEFAULT 0,
    tx_bytes BIGINT NOT NULL DEFAULT 0,
    connections INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
```

## audit_logs

```sql
CREATE TABLE audit_logs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    user_id TEXT,
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    ip TEXT,
    user_agent TEXT,
    metadata TEXT,
    created_at TEXT NOT NULL
);
```

---

# 21. Web API

Base：

```text
/api/v1
```

## Authentication

```text
POST /auth/login
POST /auth/logout
POST /auth/refresh
GET  /auth/me
```

## Enrollment

```text
POST /enroll
```

用一次性 bootstrap token 换取 Node 身份与运行时凭据（用于 `tunnel-agent register`，走 HTTPS 管理面，非 QUIC 数据面）。

## Nodes

```text
GET    /nodes
POST   /nodes
GET    /nodes/:id
PATCH  /nodes/:id
DELETE /nodes/:id

POST /nodes/:id/credentials
POST /nodes/:id/credentials/:credential_id/revoke
```

## Routes

```text
GET    /routes
POST   /routes
GET    /routes/:id
PATCH  /routes/:id
DELETE /routes/:id
POST   /routes/:id/enable
POST   /routes/:id/disable
```

## Users

```text
GET    /users
POST   /users
PATCH  /users/:id
DELETE /users/:id
```

## Roles / ACL

```text
GET    /roles
POST   /roles
PATCH  /roles/:id
DELETE /roles/:id

GET    /acl-rules
POST   /acl-rules
DELETE /acl-rules/:id
```

## Logs

```text
GET /logs
GET /audit-logs
```

## Metrics

```text
GET /metrics
GET /nodes/:id/metrics
GET /routes/:id/metrics
```

---

# 22. API 错误格式

统一：

```json
{
  "error": {
    "code": "ROUTE_NOT_FOUND",
    "message": "Route does not exist",
    "request_id": "..."
  }
}
```

HTTP：

```text
400 validation
401 authentication
403 authorization
404 not found
409 conflict
422 semantic validation
429 rate limit
500 internal error
503 unavailable
```

---

# 23. WebSocket

Endpoint：

```text
/ws
```

（需携带与 HTTP API 相同的认证凭据——Cookie 或 Bearer token。）

消息：

```json
{
  "type": "node.status",
  "data": {
    "node_id": "...",
    "status": "online"
  }
}
```

事件：

```text
node.created
node.updated
node.online
node.offline

route.created
route.updated
route.deleted

config.updated

traffic.updated
log.created
```

---

# 24. Web Dashboard

页面：

```text
/login

/
/dashboard

/nodes
/nodes/:id

/routes
/routes/new
/routes/:id

/domains
/certificates

/users
/roles

/access-control

/logs
/audit

/settings
```

Dashboard：

```text
Nodes Online
Active Tunnels
Active Connections
Traffic In
Traffic Out
Errors
```

---

# 25. Node 页面

显示：

```text
Node Name
Status
Hostname
OS
Architecture
Agent Version
Remote Address
Connected Since
Last Seen
```

统计：

```text
Active Streams
Connections
RX
TX
Errors
Latency
```

---

# 26. Route 页面

显示：

```text
Name
Type
Node
Listen
Domain
Target
Status
Connections
RX
TX
```

操作：

```text
Enable
Disable
Edit
Delete
Test
View Logs
```

---

# 27. 创建 Route

Web 表单：

```text
Type:
    TCP
    UDP
    HTTP
    HTTPS

Node:
    home

Listen:
    0.0.0.0:8080

Domain:
    optional

Target:
    192.168.1.100:80

TLS:
    terminate
    passthrough
    disabled
```

保存之后：

```text
DB
 ↓
Config Manager
 ↓
Route Manager
 ↓
Session Manager
 ↓
Agent
```

---

# 28. 热配置

数据库提交成功后产生：

```text
受影响 Node 的 config_version += 1
```

Server 内存中的配置使用：

```text
ArcSwap
```

或等价的不可变配置快照方案。

更新：

```text
DB
 ↓
load
 ↓
validate
 ↓
atomic replace
 ↓
broadcast
```

Agent：

```text
CONFIG_UPDATE
      |
validate
      |
apply
      |
ACK
```

如果 Agent ACK 失败：

```text
node.config_status = failed
```

Web 显示错误。

---

# 29. 配置事务

不能出现：

```text
数据库已经修改
Server 内存没修改
Agent 没更新
```

应该：

```text
BEGIN
  validate
  update DB
COMMIT

reload
broadcast
```

如果 Agent 无法应用：

```text
DB state = desired state
Agent state = previous state
```

系统必须显示：

```text
Pending
```

而不是假装成功。

---

# 30. ACL

支持：

```text
allow
deny
```

匹配：

```text
CIDR
IP
port
hostname
user
node
route
```

例如：

```text
allow 10.0.0.0/8
deny 0.0.0.0/0
```

默认：

```text
deny
```

对于管理 API 与 Tunnel 数据面都应分别设计权限。§20 的 `acl_rules` 已支持 `source_cidr / source_port / target_host / target_port` 等匹配字段；"user / node / route" 维度的约束通过 RBAC（§31）与 Route 的 `node_id` 归属共同实现。

---

# 31. RBAC

默认角色：

```text
admin
operator
viewer
```

权限：

```text
nodes.read
nodes.write

routes.read
routes.write

users.read
users.write

logs.read
audit.read

settings.read
settings.write
```

---

# 32. 安全

必须：

- HTTPS
- TLS 1.3
- Password hashing
- Token hashing
- CSRF 防护（Cookie Session 模式）
- CORS 限制
- Rate limiting
- Login brute-force protection
- Audit log
- RBAC
- Credential revoke
- Credential expiration
- ACL
- 最大连接数
- 最大 Stream 数
- 最大请求体
- UDP 限速

QUIC 已把 TLS 1.3 集成到传输建立过程中，提供防窃听、防篡改与防伪造。

> **UDP 反射/源地址欺骗**：公网 UDP 监听天然可被用于反射放大攻击（伪造源地址把放大流量打向目标）。至少要做到：(1) 对每个源 IP 的 UDP 会话数、发包速率、字节数做独立限速；(2) 未建立会话的入向包默认丢弃或严格限制；(3) 记录并可封禁异常源。

---

# 33. Agent 安全

Agent 默认不允许 Web 用户直接指定任意目标：

```text
127.0.0.1:22
localhost:3306
169.254.169.254
```

应由 Server 配置允许目标。

Agent 还应提供本地 ACL：

```toml
[security]

allow_targets = [
    "192.168.1.0/24"
]

deny_targets = [
    "127.0.0.0/8",
    "169.254.0.0/16"
]
```

防止 Tunnel 变成任意内网扫描器。

> **注意**：默认拒绝 `127.0.0.0/8` 意味着无法隧道到 Agent 自身的 localhost 服务；如需（如转发本机开发端口），须由管理员显式加入 `allow_targets`。

---

# 34. Reconnect

Agent：

```text
connect
 |
 +-- failed
 |
 +-- retry
```

指数退避：

```text
1s
2s
4s
8s
16s
30s
60s
```

（60s 封顶）加入随机 jitter。

网络恢复后：

```text
reconnect
authentication
config sync
online
```

---

# 35. 心跳

控制流：

```text
PING
PONG
```

默认：

```text
interval = 15s
timeout = 45s
```

指标：

```text
last_ping
last_pong
rtt
```

---

# 36. 优雅关闭

Server：

```text
stop accepting
 ↓
notify agents
 ↓
stop new streams
 ↓
wait active streams
 ↓
close sessions
```

Agent：

```text
stop new connections
 ↓
finish active connections
 ↓
close QUIC
```

超时后强制关闭。

---

# 37. 连接限制

全局：

```text
max_agents
max_streams
max_connections
max_udp_sessions
```

Node：

```text
max_streams
max_connections
max_bandwidth
```

Route：

```text
max_connections
max_connection_rate
max_bandwidth
```

---

# 38. 监控

Prometheus 指标：

```text
tunnel_nodes_online
tunnel_nodes_total

tunnel_sessions_active
tunnel_streams_active

tunnel_connections_total
tunnel_connections_failed

tunnel_bytes_received_total
tunnel_bytes_sent_total

tunnel_udp_packets_total

tunnel_route_errors_total

tunnel_agent_reconnect_total
```

---

# 39. 日志

使用 tracing。

日志级别：

```text
error
warn
info
debug
trace
```

结构化：

```json
{
  "timestamp": "...",
  "level": "INFO",
  "component": "session",
  "node_id": "...",
  "route_id": "...",
  "trace_id": "...",
  "event": "stream_open"
}
```

不要记录：

```text
password
token
private key
session cookie
完整业务 payload
```

---

# 40. 审计

所有管理操作记录：

```text
login
logout
node.create
node.delete
credential.create
credential.revoke

route.create
route.update
route.delete
route.enable
route.disable

user.create
user.update
user.delete

settings.update
```

---

# 41. Domain 管理

Domain 表：

```text
id
hostname
route_id
tls_mode
certificate_id
enabled
```

支持：

```text
app.example.com
*.example.com
```

Wildcard 必须明确限制权限。

---

# 42. Certificate 管理

支持：

```text
ACME
Let's Encrypt
manual certificate
```

Server 保存：

```text
certificate
private_key
expires_at
```

私钥必须加密保存或使用外部 Secret Store。

---

# 43. DNS

第一版不需要自己实现 DNS Server。

但可以预留：

```text
DNS provider
```

以后支持：

```text
Cloudflare
Route53
AliDNS
```

用于自动 DNS challenge。

---

# 44. Server 配置

Server 本地只保存基础启动配置：

```toml
[http]
bind = "0.0.0.0:443"        # 公网 HTTPS 统一入口：Web UI + REST API + WS + HTTP 隧道

[quic]
bind = "0.0.0.0:443"        # UDP 443，Agent QUIC 隧道（与上方 TCP 443 不冲突）

[internal]
bind = "127.0.0.1:8080"     # 仅回环：Web 管理后台 + /metrics、本地健康检查、调试
web_dir = "/app/web/dist"   # Web 管理后台静态目录（web/dist 构建产物）；缺省则不托管前端

[database]
url = "sqlite://tunnel.db"  # 生产可改为 postgres://...

[logging]
level = "info"
```

**业务 Tunnel 配置不放这里。**

业务配置全部进入数据库并由 Web 管理。

> **IPv6**：监听地址应支持 IPv6（如 `[::]:443` 双栈），Route 的 `listen_host` / `target_host` 也需能表达 IPv6 地址。第一版至少要保证 v4/v6 单栈可分别部署。

---

# 45. Agent 配置

Agent 只需要 Bootstrap 配置：

```toml
[server]
endpoints = [
    "tunnel.example.com:443"
]

[auth]
token = "..."

[agent]
name = "home"

[data]
directory = "/var/lib/tunnel-agent"
```

之后 Tunnel 配置由 Server 下发。

---

# 46. Agent CLI

```bash
tunnel-agent register
tunnel-agent run
tunnel-agent status
tunnel-agent doctor
tunnel-agent version
```

安装：

```bash
curl ... | sh
```

也支持：

```bash
apt
rpm
docker
systemd
```

---

# 47. Server CLI

```bash
tunnel-server init
tunnel-server migrate
tunnel-server start
tunnel-server check
tunnel-server version
```

初始化：

```bash
tunnel-server init
```

生成：

```text
database
server certificate
admin user
secret
```

---

# 48. Docker

Server：

```yaml
services:
  tunnel-server:
    image: ghcr.io/project/tunnel-server
    ports:
      - "443:443/tcp"              # HTTPS + Web/API + HTTP 隧道入口
      - "443:443/udp"              # QUIC 隧道（Agent 连接）
      - "127.0.0.1:8080:8080"      # 回环 internal（不暴露公网）
    volumes:
      - ./data:/data
    user: "65532:65532"            # 非 root
    restart: unless-stopped
```

生产环境推荐：

```text
443 TCP -> HTTPS/API
443 UDP -> QUIC
```

注意 UDP 443 必须在防火墙、安全组和 Docker 网络层同时开放。管理 API 走公网 443 的 HTTPS 统一入口；回环 8080 只用于本机 metrics/调试，不对外发布。

---

# 49. systemd

Server：

```text
/etc/systemd/system/tunnel-server.service
```

Agent：

```text
/etc/systemd/system/tunnel-agent.service
```

Agent：

```text
Restart=always
RestartSec=5
```

并使用：

```text
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
```

根据目标访问需求调整 sandbox 权限。

---

# 50. 高可用设计

第一版数据库：

```text
PostgreSQL
```

Server：

```text
Server A
Server B
Server C
```

共享：

```text
PostgreSQL
Redis optional
```

Agent：

```toml
[[servers]]
address = "a.example.com:443"

[[servers]]
address = "b.example.com:443"

[[servers]]
address = "c.example.com:443"
```

Agent 选择：

```text
primary
fallback
```

后续可实现 Session migration，但第一版不要求已有 TCP Stream 在 Server 故障后无损迁移。

> **UDP 负载均衡**：多 Server 前置 LB 时，QUIC/UDP 流量必须按 **QUIC Connection ID**（或源四元组）做一致性哈希/会话亲和，保证同一连接的所有 datagram 始终落到同一后端；TCP 443 也需要会话亲和（源 IP 哈希或粘性）。否则 UDP 连接会在后端间漂移导致断流。

---

# 51. HA 原则

控制面：

```text
PostgreSQL
```

数据面：

```text
Agent <-> Server
```

不能依赖数据库传输 Tunnel 数据。

数据库只保存：

```text
configuration
identity
metadata
audit
```

Tunnel payload 永远走：

```text
QUIC
```

---

# 52. HTTP Gateway

Server HTTP 层：

```text
TLS listener
    |
HTTP parser
    |
Host router
    |
Route
    |
Agent Session
```

HTTP Route 支持：

```text
Host
Path
Method
Headers
```

第一版至少：

```text
Host
```

高级路由以后加入。

> **实现建议**：HTTP 层应使用成熟库（`hyper`/`axum`）解析与转发，而不是手写 HTTP parser（符合 §2 "优先使用成熟 crate" 原则）。Host 路由与 `X-Forwarded-*` 注入都由该层完成。

---

# 53. TCP Proxy

TCP Listener：

```rust
TcpListener::bind(listen_addr)
```

接受：

```text
TcpStream
```

查找：

```text
listen_addr -> route
```

选择：

```text
node
```

打开：

```text
QUIC bidirectional stream
```

然后：

```text
copy_bidirectional
```

---

# 54. UDP Proxy

Server：

```text
UdpSocket
```

建立：

```text
client endpoint -> UDP session
```

映射：

```text
(client_addr, route_id)
```

到：

```text
QUIC datagram / logical UDP session
```

需要 session timeout。

> **源地址欺骗防护**：UDP 会话建立前，入向包不做转发或只做严格限速的临时缓冲；对伪造源地址的包（无对应会话、速率异常）直接丢弃并计数。

---

# 55. Stream 生命周期

```text
OPEN
  |
CONNECTING
  |
OPEN
  |
HALF_CLOSED
  |
CLOSED
```

异常：

```text
FAILED
```

状态必须可观测。

---

# 56. 错误码

协议错误：

```text
AUTH_FAILED
NODE_DISABLED
ROUTE_NOT_FOUND
ROUTE_DISABLED
TARGET_UNREACHABLE
TARGET_TIMEOUT
TARGET_DENIED
RESOURCE_LIMIT
CONFIG_INVALID
PROTOCOL_ERROR
INTERNAL_ERROR
```

---

# 57. 配置验证

Route 创建前必须验证：

```text
listen port
target port
hostname
node exists
node online/offline policy
duplicate listen
duplicate hostname
ACL
TLS certificate
```

例如不能：

```text
TCP :8080
TCP :8080
```

两个 Route 同时占用相同监听地址。

HTTP：

```text
app.example.com
app.example.com
```

同样禁止冲突。

---

# 58. 配置状态

Route：

```text
draft
pending
active
degraded
error
disabled
```

例如：

```text
数据库 active
Agent offline
```

UI 显示：

```text
Degraded
Agent offline
```

而不是：

```text
Online
```

---

# 59. 测试

## Unit Test

测试：

```text
config validation
route matching
ACL
authentication
protocol encoding
protocol decoding
database
```

## Integration Test

```text
Server
Agent
Target service
```

完整测试：

```text
Client
 ↓
Server
 ↓
Agent
 ↓
Target
```

## Network Test

测试：

```text
packet loss
latency
reconnect
server restart
agent restart
UDP loss
large payload
slow client
slow target
```

---

# 60. Fuzz Test

重点 fuzz：

```text
protocol decoder
HTTP parser
config parser
route matcher
authentication message
```

禁止：

```text
panic
OOM
unbounded allocation
integer overflow
```

---

# 61. 性能目标

初期目标：

```text
10,000 Agent connections
100,000 concurrent Streams
```

单 Route：

```text
10,000 concurrent TCP connections
```

具体性能必须通过 benchmark 决定，不在开发阶段假定固定吞吐数字。

关注：

```text
CPU
RAM
packet loss
latency
connection setup
throughput
```

---

# 62. Backpressure

必须避免：

```text
fast producer
      ↓
unbounded buffer
      ↓
OOM
```

使用：

```text
bounded channel
QUIC flow control
TCP backpressure
```

所有 queue 都设置上限。

> **注意（双层流控）**：TCP-over-QUIC 存在"内层 TCP 流控 + 外层 QUIC stream 流控"两层背压。数据面需正确桥接二者：TCP 读阻塞要能反向传导到 QUIC stream 的发送窗口，QUIC stream 写阻塞要能反向传导到 TCP 的读取（避免读空循环与不必要缓冲）。

---

# 63. Resource Limits

每个：

```text
Server
Node
User
Route
Connection
```

都可以配置：

```text
max_connections
max_streams
max_bandwidth
max_request_size
max_udp_session
```

---

# 64. 数据保留

实时数据：

```text
Memory
```

历史统计：

```text
Database
```

不要把每一个数据包写数据库。

例如每 10 秒聚合：

```text
rx_bytes
tx_bytes
connections
errors
```

（聚合结果写入 §20 的 `traffic_stats` 表。）

---

# 65. Web 前端目录

```text
web/
├── src/
│   ├── api/
│   ├── auth/
│   ├── components/
│   ├── layouts/
│   ├── pages/
│   ├── stores/
│   ├── websocket/
│   ├── routes/
│   └── types/
├── public/
└── package.json
```

（`web/` 是 TypeScript 前端工程，独立于 Cargo workspace。）

---

# 66. UI 设计

左侧：

```text
Dashboard

Nodes
Routes
Domains
Certificates

Users
Roles
ACL

Logs
Audit

Settings
```

顶部：

```text
Server status
notifications
user
logout
```

---

# 67. Dashboard

必须实时显示：

```text
Online Nodes
Offline Nodes
Active Routes
Active Connections
Traffic
Errors
```

图表：

```text
Traffic RX/TX
Connections
Latency
Errors
```

---

# 68. 权限控制

前端隐藏按钮只是 UX。

真正权限必须在 Server：

```text
GET /nodes
```

检查：

```text
nodes.read
```

```text
POST /routes
```

检查：

```text
routes.write
```

---

# 69. Session Authentication

Web 推荐：

```text
HttpOnly Secure SameSite cookie
```

或者：

```text
short-lived access token
refresh token
```

不要把长期 token 放 localStorage。

---

# 70. 密码

使用成熟 password hashing：

```text
Argon2id
```

禁止：

```text
MD5
SHA1
SHA256(password)
```

---

# 71. Secret

数据库：

```text
secret_hash
```

Web 创建：

```text
显示一次
```

之后：

```text
只允许 revoke + regenerate
```

---

# 72. API Rate Limit

登录：

```text
严格限速
```

管理 API：

```text
较宽松
```

Tunnel：

```text
按 Node / Route 限制
```

---

# 73. 部署架构

单机：

```text
Internet
   |
   v
VPS
 |
 +-- Tunnel Server
 +-- PostgreSQL
 +-- Web
```

生产：

```text
Internet
   |
Load Balancer
   |
+-- Server A
+-- Server B
+-- Server C
        |
    PostgreSQL
```

Agent：

```text
Internet
   |
NAT
   |
Agent
```

---

# 74. 端口规划

推荐：

```text
443/udp    QUIC Tunnel（Agent 数据面）
443/tcp    HTTPS 统一入口（Web UI + REST API + WS + HTTP 隧道）
```

内部（仅回环）：

```text
127.0.0.1:8080   internal（metrics / 本地健康检查 / 调试）
```

管理 API 与 Web UI 在生产环境统一走 443 的 HTTPS 入口（可按域名区分 `admin.example.com` 与 `*.example.com`）；回环 8080 不对外发布。

---

# 75. 域名

推荐：

```text
tunnel.example.com
```

管理：

```text
admin.example.com
```

业务：

```text
app.example.com
ssh.example.com
nas.example.com
```

---

# 76. Server 与 Web 部署

开发：

```text
Web dev server
       |
       v
Axum API
```

生产：

```text
Axum
  |
  +-- static Web assets
  |
  +-- REST API
  |
  +-- WebSocket
```

这样可以单进程部署。（管理 API 与隧道 HTTP 入口共用同一个 443 HTTPS 网关，由 Host 区分。）

---

# 77. 数据库迁移

使用 SQLx migrations：

```text
migrations/
├── 0001_initial.sql
├── 0002_acl.sql
├── 0003_certificates_domains.sql
├── 0004_traffic_stats.sql
```

部署：

```bash
tunnel-server migrate
```

---

# 78. 配置热更新流程

完整流程：

```text
Web
 |
 | PATCH /routes/:id
 v
API
 |
 | validate
 v
Database
 |
 | commit
 v
Config Manager
 |
 | version++
 v
Route Manager
 |
 v
Session Manager
 |
 | CONFIG_UPDATE
 v
Agent
 |
 | validate
 v
Agent Runtime
 |
 | ACK
 v
Server
 |
 v
WebSocket
 |
 v
Web Dashboard
```

实现要点：路由变更 DB commit 后，除了 `config_version + 1` 并向在线 Agent 推全量快照（§28），
还触发 server 端 `ConfigManager::reload`（load → validate → replace → broadcast）；main 中的
订阅任务据此 reconcile 数据面路由表——HTTP/HTTPS 走 `HostTable`、TCP 走 `TcpProxy::reconcile`
重建监听。UDP 监听暂不支持热更新。

---

# 79. Server 内部模块

```text
server/
├── api/
├── auth/
├── certificate/
├── config/
├── gateway/
│   ├── tcp/
│   ├── udp/
│   └── http/
├── session/
├── route/
├── node/
├── protocol/
├── database/
├── metrics/
├── audit/
└── main.rs
```

---

# 80. Agent 内部模块

```text
agent/
├── connection/
├── authentication/
├── config/
├── proxy/
│   ├── tcp/
│   ├── udp/
│   └── http/
├── health/
├── metrics/
├── runtime/
└── main.rs
```

---

# 81. Core Trait

核心抽象建议：

```rust
trait TunnelTransport {
    async fn connect(&self) -> Result<Session>;
}

trait RouteHandler {
    async fn handle(&self, connection: IncomingConnection) -> Result<()>;
}

trait TargetConnector {
    async fn connect(&self, target: Target) -> Result<TcpStream>;
}
```

不要让 Web/API 层直接操作 Quinn Connection。

---

# 82. Session Manager

维护：

```text
Node ID -> Session
```

例如：

```rust
HashMap<NodeId, Arc<NodeSession>>
```

（并发访问需用 `DashMap` 或 `RwLock<HashMap>` 保护。）

NodeSession：

```text
node_id
connection
status
connected_at
last_seen
config_version
active_streams
```

---

# 83. Route Manager

维护：

```text
Route ID
Listen address
Hostname
Node ID
Target
```

需要快速查找：

```text
listen -> route
hostname -> route
```

因此使用：

```text
HashMap
DashMap
ArcSwap
```

等并发结构。

---

# 84. Connection Registry

每个连接产生：

```text
connection_id
```

保存：

```text
route_id
node_id
created_at
remote_addr
bytes_in
bytes_out
state
```

关闭后释放。

---

# 85. 不保存业务数据

Tunnel Server 默认：

```text
不保存 payload
不解析 SSH
不记录 HTTP body
不记录密码
```

除非用户显式启用相关调试功能。

---

# 86. Debug 模式

允许：

```text
protocol logs
connection logs
route logs
```

默认：

```text
payload logging = disabled
```

---

# 87. Observability

每个请求/连接生成：

```text
trace_id
```

跨组件：

```text
Web
 ↓
Server
 ↓
Session
 ↓
Agent
 ↓
Target
```

都使用同一个 correlation ID。

---

# 88. Version Compatibility

协议包含：

```text
protocol_version
agent_version
server_version
```

Server：

```text
min_agent_version
```

Agent 太旧：

```text
upgrade_required
```

---

# 89. Protocol Version

例如：

```text
major = 1
minor = 0
```

规则：

```text
major 不兼容
minor 向后兼容
```

未知 message：

```text
ignore if optional
close if required
```

---

# 90. Graceful Upgrade

Server 更新：

```text
old sessions continue
new sessions use new version
```

Agent：

```text
download new version
restart
reconnect
```

以后再实现：

```text
rolling upgrade
```

---

# 91. 备份

必须备份：

```text
database
server identity
TLS certificates
configuration
```

不要备份：

```text
temporary runtime state
```

---

# 92. Disaster Recovery

恢复顺序：

```text
install Server
 ↓
restore database
 ↓
restore certificates
 ↓
start Server
 ↓
Agents reconnect
 ↓
configuration restored
```

---

# 93. 安装体验

目标：

```bash
curl -fsSL https://example.com/install-agent.sh | sh
```

然后：

```bash
tunnel-agent register \
  --server https://tunnel.example.com \
  --token XXXX
```

或者 Web 生成安装命令：

```text
[Copy Install Command]
```

> **注册信任链**：`register` 使用 Web 管理员预置的一次性 bootstrap token，通过 HTTPS 管理面（`POST /enroll`）换取 Node 身份与运行时凭据；之后 Agent 才用 QUIC 连接。Agent 不是"匿名自助注册"——必须先有管理员预置的 token。

---

# 94. Agent Bootstrap

Agent 启动：

```text
read bootstrap config
        |
resolve server
        |
connect QUIC
        |
authenticate
        |
receive config
        |
start proxy
        |
heartbeat
```

---

# 95. Agent 本地配置优先级

```text
CLI
 ↓
Environment
 ↓
Config file
 ↓
Server configuration
```

但是 Tunnel Route 不允许 Agent 本地覆盖 Server 强制策略。

---

# 96. Environment Variables

支持：

```text
TUNNEL_SERVER
TUNNEL_TOKEN
TUNNEL_NODE
TUNNEL_LOG
TUNNEL_DATA_DIR
```

---

# 97. Health Check

Server：

```text
GET /health
GET /ready
```

Agent：

```text
local health endpoint
```

例如：

```text
127.0.0.1:9090/health
```

---

# 98. Readiness

Server Ready 必须满足：

```text
database connected
configuration loaded
QUIC listener ready
HTTP listener ready
```

---

# 99. Backup API

Web：

```text
Settings
 → Backup
```

生成：

```text
configuration export
```

导入前必须：

```text
validate
preview
confirm
```

不能直接覆盖生产配置。

---

# 100. Import/Export

支持：

```yaml
nodes:
routes:
domains:
acl:
```

Credential 不允许普通导出。

> **格式区分**：导入/导出的 `YAML` 是**数据库配置快照的序列化格式**（控制面数据），与 Server/Agent 启动用的 **Bootstrap TOML**（§44/§45）是不同用途、不同文件，二者并存不冲突。

---

# 101. 多租户预留

如果以后支持 SaaS：

```text
organization
project
user
node
route
```

关系：

```text
Organization
   |
   +-- Users
   +-- Nodes
   +-- Routes
   +-- Domains
```

第一版即使只支持一个 Organization，§20 的核心表已预留 `tenant_id`（默认 `'default'`），后续 SaaS 化只需增加 `organizations` 表并按 tenant 过滤，无需重构主键。

---

# 102. API Token

除了 Web Session：

```text
Personal API Token
```

用于：

```text
CI/CD
Terraform
CLI
Automation
```

格式：

```text
token_xxxxxxxxx
```

数据库只保存 hash。

---

# 103. CLI

未来：

```bash
tunnel login
tunnel node list
tunnel node create
tunnel route list
tunnel route create
tunnel route delete
```

CLI 调 REST API。

这样：

```text
Web
CLI
API
```

共享同一个控制面。

---

# 104. Terraform

以后可以支持：

```text
tunnel_node
tunnel_route
tunnel_domain
tunnel_acl
```

这样整个系统可以 IaC 管理。

---

# 105. Security Boundary

必须明确：

```text
Control Plane
    |
    | configuration
    v
Data Plane
    |
    | traffic
    v
Agent
```

Web 用户不能直接获得：

```text
Agent shell
```

Server 不能因为 Route 配置而默认拥有 Agent 上的任意执行能力。

---

# 106. 防止 SSRF

目标地址必须检查：

```text
loopback
link-local
multicast
broadcast
private ranges
metadata services
```

策略可以由管理员明确允许。

尤其：

```text
169.254.169.254
```

默认拒绝。

---

# 107. 防止资源耗尽

所有输入都有：

```text
maximum size
timeout
rate limit
concurrency limit
```

绝不允许：

```text
unbounded Vec
unbounded channel
unbounded cache
```

---

# 108. Timeout

推荐默认：

```text
connect timeout       10s
open result timeout   15s
idle TCP timeout      disabled/route configurable
UDP idle timeout      60s
HTTP request timeout  60s
auth timeout          10s
config ACK timeout    10s
heartbeat timeout     45s
```

具体默认值必须通过实际测试调整。

---

# 109. TCP Half Close

必须正确处理：

```text
FIN
RST
EOF
```

不能简单：

```text
read == 0 -> immediately close both directions
```

要支持 half-close。

---

# 110. HTTP Header

默认保留：

```text
Host
X-Forwarded-For
X-Forwarded-Proto
X-Forwarded-Host
```

安全要求：

Server 必须覆盖来自不可信客户端的：

```text
X-Forwarded-For
```

不能直接信任客户端伪造值。

---

# 111. Client IP

HTTP：

```text
X-Forwarded-For
```

TCP：

Agent 可以获得：

```text
original source IP
```

如果需要透明传递，可以后增加 PROXY protocol：

```text
PROXY v2
```

第一版不强制。

---

# 112. UDP Source IP

UDP 模式需要定义：

```text
original_client_ip
original_client_port
```

Tunnel metadata 不能直接暴露给不可信目标。

---

# 113. Web Admin API 与 Tunnel Listener 分离

统一入口（推荐）：

```text
0.0.0.0:443/tcp
 ├── HTTPS（Web UI + REST API + WS）
 └── HTTP 隧道入口（按 Host 分发）

0.0.0.0:443/udp
 └── QUIC 隧道（Agent）

127.0.0.1:8080
 └── internal（metrics / 本地健康检查 / 调试）
```

公网入口由统一 TLS Gateway 按 Host 分发（`admin.example.com` 走管理面，`*.example.com` 走业务隧道）。

---

# 114. 证书策略

至少：

```text
Server certificate
Admin certificate
Domain certificates
```

Server 与 Agent：

```text
QUIC TLS
```

使用 Server CA / public CA。

如果采用 mTLS：

```text
Server cert
Client cert
```

可以实现双向身份认证。

---

# 115. 推荐认证模型

第一版：

```text
Web:
username + password + session

Agent:
预置 token（TLS 保护下）+ 应用层 AUTH

API:
Bearer token
```

高级：

```text
Agent mTLS
```

> **说明**：Agent 侧 TLS 由 QUIC 的服务器证书完成（保证 Agent 连的是可信 Server）；Agent 自身身份由凭据 token（或 mTLS 客户端证书）在应用层 `AUTH` 中证明，二者配合完成双向认证。

---

# 116. 协议认证

TLS 认证完成后，应用层仍发送：

```text
HELLO
AUTH
```

因为应用层需要知道：

```text
node_id
credential
protocol version
capabilities
```

---

# 117. Capabilities

Agent 登录时报告：

```json
{
  "tcp": true,
  "udp": true,
  "http": true,
  "websocket": true,
  "quic": true
}
```

Server 根据 capability 下发配置。

---

# 118. Server Capability

以后可以：

```text
http3
tcp
udp
tls_passthrough
```

---

# 119. 连接调度

一个 Node 可以有多个 Session：

```text
Node
 |
 +-- Session 1
 +-- Session 2
 +-- Session 3
```

第一版：

```text
one node -> one active session
```

架构必须允许未来：

```text
one node -> N sessions
```

用于并发与 HA。

---

# 120. Stream Scheduling

选择 Agent Session：

```text
least_connections
round_robin
least_load
```

第一版：

```text
single session
```

以后：

```text
least_connections
```

---

# 121. Traffic Accounting

每个 Route：

```text
bytes_in
bytes_out
connections
errors
```

每个 Node：

```text
bytes_in
bytes_out
streams
```

全局：

```text
total traffic
```

---

# 122. Metrics Aggregation

实时：

```text
memory
```

持久化：

```text
10s / 60s aggregate
```

避免高频写 DB。

---

# 123. Log Rotation

本地：

```text
journald
```

或：

```text
rolling file
```

Docker：

```text
stdout
stderr
```

生产推荐交给日志系统。

---

# 124. CI

GitHub Actions：

```text
fmt
clippy
test
build
audit
deny
```

矩阵：

```text
Linux x86_64
Linux ARM64
Windows
macOS
```

Agent 至少重点支持：

```text
Linux x86_64
Linux ARM64
Windows x86_64
```

---

# 125. Release

产物：

```text
tunnel-server
tunnel-agent
```

Docker：

```text
ghcr.io/project/tunnel-server
ghcr.io/project/tunnel-agent
```

版本：

```text
Semantic Versioning
```

---

# 126. Docker Image

Server：

```text
debian-slim / distroless
```

Agent：

```text
debian-slim
```

不要默认 root。

---

# 127. Windows Agent

必须支持：

```text
Windows Service
```

Agent 不依赖 shell。

---

# 128. Linux Agent

支持：

```text
systemd
```

自动：

```text
restart
network-online
```

---

# 129. macOS Agent

支持：

```text
launchd
```

---

# 130. 配置 UI 与数据库模型的关系

不要让前端直接构造任意 JSON。

前端：

```text
Form
 ↓
typed API
 ↓
Server validation
 ↓
DB
```

Server 永远是最终 authority。

---

# 131. API Schema

建议使用 OpenAPI：

```text
/openapi.json
/docs
```

自动生成：

```text
TypeScript client
Rust client
```

---

# 132. Web 类型

从 OpenAPI 生成：

```text
Node
Route
User
Certificate
Metrics
AuditLog
```

避免前后端手写重复类型。

---

# 133. Database Transaction

创建 Route：

```text
BEGIN

validate node
validate listener
validate hostname
validate target
validate ACL

INSERT route
INSERT audit log

COMMIT
```

---

# 134. Event System

Server 内部事件：

```text
NodeOnline
NodeOffline
RouteCreated
RouteUpdated
RouteDeleted
ConfigChanged
StreamOpened
StreamClosed
```

使用：

```text
tokio broadcast
```

或内部 EventBus。

WebSocket 订阅这些事件。

---

# 135. Cache

数据库不是所有请求的实时数据源。

配置：

```text
DB -> Config Cache
```

Node status：

```text
memory
```

Metrics：

```text
memory + Prometheus
```

---

# 136. Server Restart

启动：

```text
DB
 ↓
load config
 ↓
validate config
 ↓
bind listeners
 ↓
start API
 ↓
accept agents
```

Agent 自动恢复。

---

# 137. Agent Restart

```text
read bootstrap
 ↓
connect
 ↓
auth
 ↓
config snapshot
 ↓
routes active
```

---

# 138. Server 更新 Route 时

不能立即关闭现有连接。

默认：

```text
existing connections -> continue
new connections -> new config
```

删除 Route：

```text
stop accepting new
existing -> drain
```

---

# 139. Route Drain

状态：

```text
active
draining
disabled
deleted
```

管理员删除：

```text
draining
```

等：

```text
active_connections == 0
```

再删除运行时对象。

---

# 140. Web 操作确认

危险操作：

```text
Delete Node
Delete Route
Revoke Credential
Delete Certificate
```

必须二次确认。

---

# 141. Audit Example

```json
{
  "action": "route.update",
  "resource_id": "...",
  "user_id": "...",
  "ip": "...",
  "metadata": {
    "changed": [
      "target_port"
    ]
  }
}
```

---

# 142. 测试拓扑

开发测试：

```text
Host
├── server
├── agent
└── target
```

Docker：

```text
server
agent
target
client
```

测试：

```text
curl
netcat
iperf3
socat
dig
```

---

# 143. TCP 测试

```text
client
 ↓
server:8080
 ↓
agent
 ↓
target:80
```

验证：

```text
small payload
large payload
long connection
half close
RST
timeout
reconnect
```

---

# 144. UDP 测试

验证：

```text
packet ordering
loss
burst
large packet
multiple clients
timeout
```

---

# 145. HTTP 测试

验证：

```text
GET
POST
large body
chunked
keep-alive
WebSocket
TLS
SNI
404
502
timeout
```

---

# 146. Failure Tests

必须测试：

```text
Agent kill
Server kill
Network disconnect
DNS failure
Target offline
Target timeout
DB restart
Certificate expiry
Credential revoke
Config invalid
```

---

# 147. Security Tests

测试：

```text
invalid token
expired token
revoked token
wrong node
unauthorized route
brute force
oversized frame
malformed protocol
invalid hostname
SSRF
ACL bypass
UDP spoofing / reflection
```

---

# 148. Protocol Fuzzing

目标：

```text
decode()
parse()
validate()
```

必须做到：

```text
任意非法输入 -> Result::Err
```

不能：

```text
panic
```

---

# 149. 性能 Benchmark

测试：

```text
1
10
100
1,000
10,000
```

Agent 数量。

测试：

```text
1
10
100
1,000
10,000
```

并发连接。

---

# 150. 项目开发顺序

不是按"学习难度"，而是按产品依赖关系：

```text
1. Workspace
2. Database
3. Protocol
4. Server QUIC
5. Agent QUIC
6. Authentication
7. Session Manager
8. TCP Proxy
9. Config Manager
10. REST API
11. Web UI
12. Hot Reload
13. HTTP
14. HTTPS
15. UDP
16. ACL
17. RBAC
18. Metrics
19. Audit
20. Deployment
21. HA
```

---

# 151. 第一阶段完成标准

Server：

```text
启动
连接数据库
启动 QUIC
启动 API
```

Agent：

```text
启动
连接 Server
认证
保持 Session
```

必须达到：

```text
Agent Online
```

---

# 152. 第二阶段完成标准

TCP：

```text
公网 :8080
     ↓
Agent
     ↓
LAN :80
```

必须能够：

```bash
curl http://VPS:8080
```

成功访问内网 HTTP 服务。

---

# 153. 第三阶段完成标准

Web：

```text
Login
Node list
Create Node
Create Route
Edit Route
Delete Route
```

配置不再依赖 TOML。

---

# 154. 第四阶段

热更新：

```text
Web 修改 Route
 ↓
DB
 ↓
Server
 ↓
Agent
```

无需：

```text
restart server
restart agent
```

---

# 155. 第五阶段

HTTP：

```text
app.example.com
```

支持：

```text
TLS
Host routing
WebSocket
```

---

# 156. 第六阶段

UDP：

```text
UDP client
 ↓
Server
 ↓
Agent
 ↓
LAN UDP
```

---

# 157. 第七阶段

安全：

```text
RBAC
ACL
Audit
Rate limit
Credential rotation
```

---

# 158. 第八阶段

运维：

```text
Prometheus
Docker
systemd
backup
restore
health
```

---

# 159. 第九阶段

HA：

```text
multiple Server
multiple Agent sessions
PostgreSQL
load balancing
```

---

# 160. 推荐默认配置

```toml
[http]
listen = "0.0.0.0:443"

[quic]
listen = "0.0.0.0:443"
max_concurrent_bidi_streams = 10000
max_concurrent_uni_streams = 1000
idle_timeout_seconds = 60

[internal]
listen = "127.0.0.1:8080"

[security]
max_login_attempts = 5
login_window_seconds = 300

[limits]
max_nodes = 10000
max_routes = 100000
max_connections_per_route = 10000

[agent]
heartbeat_interval_seconds = 15
heartbeat_timeout_seconds = 45
```

实际生产值必须根据 benchmark 调整。

---

# 161. 核心设计原则

### 原则 1

Web 是控制面。

### 原则 2

数据库是配置真源。

### 原则 3

Server 是最终 authority。

### 原则 4

Agent 主动出站。

### 原则 5

Tunnel 数据不经过数据库。

### 原则 6

QUIC 负责可靠多路复用。

### 原则 7

TLS/QUIC 使用成熟实现，不自行实现密码学。

### 原则 8

配置必须支持热更新。

### 原则 9

现有连接默认不因配置修改立即断开。

### 原则 10

所有管理操作可审计。

### 原则 11

所有资源都有上限。

### 原则 12

默认安全策略优先于便利。

---

# 162. 最终产品形态

```text
                        ┌──────────────────┐
                        │    Web Browser   │
                        └────────┬─────────┘
                                 │
                         HTTPS / WebSocket
                                 │
                                 v
+----------------------------------------------------------------+
|                         Tunnel Server                          |
|                                                                |
|  +---------+  +---------+  +---------+  +----------------+    |
|  | Web/API |  |  Auth   |  | Config  |  | Route Manager  |    |
|  +---------+  +---------+  +---------+  +----------------+    |
|                                                                |
|  +---------+  +---------+  +---------+  +----------------+    |
|  |  HTTP   |  |   TCP   |  |   UDP   |  | Session Manager |   |
|  +---------+  +---------+  +---------+  +----------------+    |
|                                                                |
|                      QUIC / TLS 1.3                            |
+-------------------------------+--------------------------------+
                                |
             +------------------+------------------+
             |                  |                  |
             v                  v                  v
        +---------+        +---------+        +---------+
        | Agent A |        | Agent B |        | Agent C |
        +----+----+        +---------+        +---------+
             |
       +-----+------+-------+
       |            |       |
      HTTP         SSH     TCP
       |            |       |
       +------------+-------+
                    |
                LAN Services
```

---

# 163. Definition of Done

项目达到正式 1.0 必须满足：

- [ ] Server 可独立部署
- [ ] Agent 可独立部署
- [ ] Web 可登录
- [ ] Node 可通过 Web 创建
- [ ] Credential 可生成/revoke
- [ ] Agent 可认证
- [ ] Agent 自动重连
- [ ] TCP Tunnel
- [ ] UDP Tunnel
- [ ] HTTP Tunnel
- [ ] HTTPS Tunnel
- [ ] WebSocket
- [ ] QUIC
- [ ] TLS 1.3
- [ ] Web Route 管理
- [ ] 配置热更新
- [ ] 配置版本
- [ ] RBAC
- [ ] ACL
- [ ] Audit
- [ ] Metrics
- [ ] Logs
- [ ] Health check
- [ ] SQLite
- [ ] PostgreSQL
- [ ] Docker
- [ ] systemd
- [ ] Linux Agent
- [ ] Windows Agent
- [ ] API
- [ ] OpenAPI
- [ ] 自动测试
- [ ] Fuzz test
- [ ] 性能测试
- [ ] 安全测试
- [ ] Backup / Restore
- [ ] 文档
- [ ] Release pipeline

---

# 164. 最终建议

项目不要把业务 Tunnel 配置放在本地 TOML 中。

最终关系应该严格保持：

```text
                    Control Plane
                         │
                    ┌────v────┐
                    │   Web   │
                    └────┬────┘
                         │
                       REST
                         │
                    ┌────v────┐
                    │ Server  │
                    └────┬────┘
                         │
                       DB
                         │
              desired configuration
                         │
                    ┌────v────┐
                    │ Session │
                    └────┬────┘
                         │
                       QUIC
                         │
                    ┌────v────┐
                    │  Agent  │
                    └────┬────┘
                         │
                     TCP/UDP
                         │
                    ┌────v────┐
                    │ Target  │
                    └─────────┘
```

**一句话定义整个系统：**

> Web 管理控制面 + Rust Tunnel Server 数据面 + Rust Agent 执行面 + PostgreSQL/SQLite 配置存储 + QUIC/TLS 安全传输。

这套架构可以从单 VPS 单 Agent 起步，但不会把后面的多 Agent、HTTP/HTTPS、UDP、ACL、RBAC、HA 和 Web 管理能力堵死。
