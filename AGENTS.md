# AGENTS.md — 开发指引

本文件面向在本仓库工作的 agent（AI 或人工）。目标是：任何一个 agent 独立领走一个任务时，产出的代码都符合项目约定、可编译、可测试、可被下一个任务复用。

权威设计文档在 `docs/rust-tunnel-design.md`；协议/建表/API/模块/计划的细节分别在 `docs/{protocol,schema,api,architecture,plan}.md`。**开始写代码前先读对应细节文档，不要凭空决定协议字节、表结构或 API 形状。**

---

## 1. 仓库布局与 crate 职责

```text
rust-tunnel/
├── AGENTS.md                 # 本文件
├── README.md
├── Cargo.toml                # workspace 根
├── crates/
│   ├── tunnel-common/        # 错误类型、tracing 初始化、通用工具（无 IO）
│   ├── tunnel-protocol/      # 帧编解码、消息类型、payload 结构（纯，可 fuzz）
│   ├── tunnel-config/        # bootstrap 配置结构 + 校验（serde + toml）
│   ├── tunnel-core/          # 核心抽象 trait 与共享类型（Route/NodeId/Session…）
│   ├── tunnel-auth/          # 密码哈希(Argon2id)、token 哈希/校验、会话
│   ├── tunnel-db/            # SQLx 数据访问层 + 迁移
│   └── tunnel-metrics/       # Prometheus 指标定义
├── server/                   # 二进制 tunnel-server
├── agent/                    # 二进制 tunnel-agent
├── web/                      # TypeScript 前端（独立工程，不参与 cargo）
├── migrations/               # SQLx 迁移脚本（由 tunnel-db embed）
├── deploy/
│   ├── docker/
│   └── systemd/
├── docs/
└── tests/                    # 跨 crate 集成测试
```

**依赖方向（不可反向）**：

```text
tunnel-common
   ↑
tunnel-protocol / tunnel-config / tunnel-auth / tunnel-metrics
   ↑
tunnel-db
   ↑
tunnel-core
   ↑
server / agent
```

`server`、`agent` 不互相依赖；`web` 不依赖任何 Rust crate。

---

## 2. 常用命令

```bash
cargo fmt --all -- --check          # 格式检查
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build --release -p tunnel-server -p tunnel-agent

# 数据库迁移（SQLite 本地开发）
export DATABASE_URL="sqlite://tunnel.db"
cargo sqlx migrate run --source migrations

# 集成测试（Docker 拓扑：server/agent/target/client）
docker compose -f deploy/docker/docker-compose.yml up
```

---

## 3. 编码约定

- **错误处理**：库 crate 用 `thiserror` 定义带上下文的错误枚举；应用边界用 `anyhow`。**禁止 `unwrap()`/`expect()`/裸 `panic!`**（除 `unreachable!` 且注释说明不可达）。
- **日志**：`tracing` 结构化字段（`node_id`、`route_id`、`trace_id`、`event`）。**绝不记录** password/token/private_key/session cookie/完整 payload。
- **并发**：共享只读配置用 `ArcSwap`；高频读 HashMap 用 `DashMap`；**所有 channel 必须 bounded**（`tokio::sync::mpsc::channel(N)` 或 `broadcast`）。
- **网络字节序**：协议编解码一律 `u32::to_be_bytes` / `u32::from_be_bytes`，禁止 `as` 隐式截断。
- **ID**：`uuid::Uuid` v4，序列化/入库为字符串（DB 用 `TEXT`）。类型别名定义在 `tunnel-core`。
- **时间**：DB/JSON 用 RFC3339 字符串；代码里用 `time::OffsetDateTime`（项目统一用 `time` crate）。
- **资源上限**：任何 `Vec`/channel/cache/缓冲都要有上限；超限返回 `RESOURCE_LIMIT` 而非无限增长（对应设计文档 §62/§107）。
- **密码学/传输**：只用 `quinn`/`rustls`/`argon2` 等成熟 crate，禁止自研（§2）。

---

## 4. 新增/修改协议消息的步骤

1. 在 `crates/tunnel-protocol/src/message.rs` 加 `MessageType` 变体（含 wire 值）。
2. 在 `crates/tunnel-protocol/src/payload.rs` 定义 payload 结构（`serde`），标注方向（A→S / S→A）。
3. 在 `codec.rs` 补 encode/decode 分支 + 单测（含非法输入 → `Err`）。
4. 同步更新 `docs/protocol.md` 的消息目录表。
5. 跑 `cargo test -p tunnel-protocol`。

---

## 5. 新增一条 Route 类型 / 字段的步骤

1. `docs/schema.md` 与 `migrations/` 同步（新列 → 新迁移，禁止改已发布迁移）。
2. `tunnel-core` 的 `Route` 结构 + `tunnel-db` 的映射。
3. `server/route` 校验逻辑（§57 冲突检查）。
4. `docs/api.md` 的请求/响应字段。
5. Web 前端表单 + 类型（OpenAPI 生成后同步）。

---

## 6. 单任务 Definition of Done

提交/交接前必须全部满足：

- [ ] `cargo fmt --all -- --check` 通过
- [ ] `cargo clippy ... -D warnings` 通过
- [ ] `cargo test --workspace` 通过
- [ ] 新增/改动逻辑有单元测试，错误路径有覆盖
- [ ] 无 `unwrap`/`expect`/裸 `panic!`
- [ ] 日志不泄露 secret/payload；trace_id 已传播
- [ ] 无 unbounded buffer/channel/cache
- [ ] 涉及协议/建表/API 的改动已同步对应 docs
- [ ] 资源上限与超时已设置（见设计文档 §108 默认值）

---

## 7. 关键红线速查

- ❌ 不要自己实现 TLS / QUIC / HTTP/2 / 密码学
- ❌ 不要在 QUIC 之上重新造 TCP 多路复用（用 QUIC stream 本身，见 §7/§8.2）
- ❌ 不要 TUNNEL 数据经过数据库（只存配置/身份/审计/统计）
- ❌ 不要把业务 Tunnel 配置写进本地 TOML（bootstrap 只放启动配置）
- ✅ Server 永远是最终 authority，前端隐藏按钮只是 UX（§68）
- ✅ 默认 deny（ACL），默认安全优先（§161 原则 12）
