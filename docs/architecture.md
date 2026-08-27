# 架构：crate 职责、核心抽象、数据流

> 本文把设计文档 §4/§79–§84 落到具体 Rust 模块与类型签名。签名是**接口示意**，实现可调整但职责边界不变。

## 1. crate 职责

| crate | 职责 | 关键内容 |
|-------|------|----------|
| `tunnel-common` | 错误、日志、工具 | `Error`、`Result`、`init_tracing`、`TraceId` |
| `tunnel-protocol` | 协议编解码（纯，可 fuzz） | `Frame`、`MessageType`、各 payload、`encode_frame`/`decode_frame` |
| `tunnel-config` | bootstrap 配置 | `ServerConfig`、`AgentConfig`、校验 |
| `tunnel-auth` | 密码/token 哈希与校验 | `hash_password`（Argon2id）、`hash_token`、`verify_token` |
| `tunnel-db` | 数据访问 | `Db`、迁移、repo 函数、`Row`→类型映射 |
| `tunnel-metrics` | 指标 | Prometheus 指标注册（§38） |
| `tunnel-core` | 共享抽象与类型 | trait、`Route`、`NodeId`、`Session`、`Target`、`ConfigSnapshot` |
| `server` | 公网数据面 + 控制面 | `api`/`auth`/`certificate`/`config`/`gateway`/`session`/`route`/`node`/`protocol`/`db`/`metrics`/`audit` |
| `agent` | 内网执行面 | `connection`/`authentication`/`config`/`proxy`/`health`/`metrics`/`runtime` |
| `cli` | 管理 CLI | 调 REST API（`tunnel login`/`node`/`route`） |

## 2. 核心类型（tunnel-core）

```rust
pub type NodeId = uuid::Uuid;
pub type RouteId = uuid::Uuid;

pub struct Target {
    pub host: String,
    pub port: u16,
}

pub enum RouteType { Tcp, Udp, Http, Https }

pub struct Route {
    pub id: RouteId,
    pub name: String,
    pub node_id: NodeId,
    pub route_type: RouteType,
    pub enabled: bool,
    pub listen: Option<ListenAddr>,      // host + port
    pub hostname: Option<String>,        // http/https
    pub target: Target,
    pub tls_mode: TlsMode,               // Terminate | Passthrough | Disabled
    pub limits: Limits,
}

pub struct ConfigSnapshot {
    pub config_version: u64,
    pub routes: Vec<Route>,
    pub acl: Vec<AclRule>,
    pub limits: Limits,
}
```

## 3. 核心 trait

```rust
// 传输抽象：隔离 quinn，避免 API/网关直接操作 Connection
#[async_trait::async_trait]
pub trait TunnelTransport {
    async fn connect(&self) -> Result<Session>;
}

// 数据面处理：TCP/HTTP/UDP 网关各自实现
#[async_trait::async_trait]
pub trait RouteHandler {
    async fn handle(&self, conn: IncomingConnection) -> Result<()>;
}

// 目标连接：Server 侧不直接连内网，由 Agent 连
#[async_trait::async_trait]
pub trait TargetConnector {
    async fn connect(&self, target: Target) -> Result<TcpStream>;
}
```

> 设计文档 §81 的三条 trait 之上，补充一条控制面接口：`ControlChannel`（发 HELLO/AUTH/CONFIG_*，收发 PING/PONG/STATS），供 session manager 与 agent runtime 共用。

## 4. 并发模型

- **配置快照**：`ArcSwap<ConfigSnapshot>`，读无锁，写原子替换（§28）。
- **Session 表**：`DashMap<NodeId, Arc<NodeSession>>`（§82）。
- **Route 索引**：`DashMap<ListenAddr, RouteId>` + `DashMap<String, RouteId>`（hostname→route，§83）。
- **连接注册表**：`DashMap<ConnectionId, ConnectionMeta>`（§84），关闭即删。
- **channel**：一律 bounded；事件总线用 `tokio::sync::broadcast`（§134）。

## 5. 关键数据流

### 5.1 Agent 上线（认证 + 配置下发）
```
agent.connection  →  QUIC connect  →  open control stream
  → HELLO(capabilities, version)
  → AUTH(credential)
server.session  →  verify → AUTH_OK  → 写 node.status=online, last_seen_at
  → CONFIG_SNAPSHOT(当前快照)
agent.config  →  应用 → CONFIG_ACK
```

### 5.2 TCP 转发
```
server.gateway.tcp  →  TcpListener 接受  →  查 listen→route  →  选 node session
  →  开 bidi stream  →  OPEN_TCP(route, target)
agent.proxy.tcp  →  读 OPEN_TCP  →  连 target  →  OPEN_OK/OPEN_FAIL
  →  copy_bidirectional（支持 half-close）
```

### 5.3 HTTP 转发
```
server.gateway.http（hyper/axum）  →  解析 Host  →  查 hostname→route
  →  覆盖 X-Forwarded-*  →  开流 OPEN_TCP（HTTP 也复用）
agent  →  连 target_host:port  →  透传原始 HTTP 字节
```

### 5.4 配置热更新
```
api  →  db 事务提交  →  config.version++  →  ArcSwap 替换
  →  session 广播 CONFIG_UPDATE(delta)
agent  →  校验/应用  →  CONFIG_ACK
  →  WebSocket 推送 config.updated 到 dashboard
```

## 6. Server 启动顺序

```text
read bootstrap → init tracing → 连 DB → migrate → load config → 校验
→ bind QUIC(0.0.0.0:443/udp) → bind HTTP(0.0.0.0:443/tcp) → bind internal(127.0.0.1:8080)
→ 构建 ArcSwap<ConfigSnapshot> + DashMap session/route
→ start API → accept agents → /ready 就绪
```

## 7. Agent 启动顺序

```text
read bootstrap → 解析 endpoints → 选 primary → QUIC connect
→ HELLO → AUTH → AUTH_OK → CONFIG_SNAPSHOT → 应用 → 启动 proxy
→ heartbeat(PING) → 断线 → 指数退避重连 → 重新认证+同步
```

## 8. 错误类型

```rust
// tunnel-common
pub enum Error {
    Protocol(ProtocolError),   // 来自 tunnel-protocol
    Auth(AuthError),
    Db(sqlx::Error),
    Route(RouteError),
    Target(TargetError),
    ResourceLimit,
    Config(ConfigError),
}
impl Error {
    pub fn code(&self) -> &'static str;   // 映射到协议错误码（protocol.md §8）
}
```
