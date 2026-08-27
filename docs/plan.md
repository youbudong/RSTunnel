# 开发计划（供 agent 执行）

> 本文把设计文档 §150–§159 的"开发顺序"展开成**可独立交付的任务**。每个任务含目标、涉及模块、关键实现点、验收标准、依赖。
> 任务编号 `T-xx`，里程碑 `M0…M11`。依赖只标"前置里程碑"，同一里程碑内任务尽量解耦。

## 里程碑总览

| 里程碑 | 目标 | 对应 DoD（设计文档 §151–159） |
|--------|------|------|
| M0 | 工作区 + 数据库 + 配置骨架 | 第 1/2 阶段前置 |
| M1 | 协议编解码 + fuzz 骨架 | 阶段 1 前置 |
| M2 | Server QUIC + 认证 + Session（Agent 上线） | §151 第一阶段 |
| M3 | Agent 连接 + 心跳 + 重连 + 配置应用 | §151 第一阶段 |
| M4 | TCP 隧道 | §152 第二阶段 |
| M5 | 配置管理与热更新 | §154 第四阶段 |
| M6 | REST API + Web UI | §153 第三阶段 |
| M7 | HTTP / HTTPS / WebSocket | §155 第五阶段 |
| M8 | UDP 隧道 | §156 第六阶段 |
| M9 | 安全：RBAC / ACL / 审计 / 限速 | §157 第七阶段 |
| M10 | 运维：监控 / Docker / systemd / 备份 | §158 第八阶段 |
| M11 | HA + 发布流水线 + 压测 | §159 第九阶段 |

> 依赖主线：M0 → M1 → M2 → M3 → M4 → M5 → M6 → M7 → M8 → M9 → M10 → M11。
> M6（API/UI）与 M7/M8 可部分并行；M9/M10 可与 M6–M8 并行。

---

## M0 — 工作区与数据库

### T-01 Workspace 与 crate 骨架
- **目标**：按 `AGENTS.md` 建 workspace + 7 个 crate + 3 个二进制骨架，跑通 `cargo build`。
- **涉及**：`Cargo.toml`、`crates/*/Cargo.toml`、`server/`、`agent/`、`cli/`、`src/main.rs`。
- **关键点**：依赖方向只允许 `common ← protocol/config/auth/metrics ← db ← core ← server/agent`；统一依赖版本（workspace deps）。
- **验收**：`cargo build --workspace` 成功；`cargo fmt`/`clippy` 通过；每个 crate 有最小 `lib.rs`。

### T-02 tunnel-common：错误与日志
- **目标**：统一 `Error`（thiserror）、`Result` 别名、`init_tracing`。
- **验收**：`Error` 有 `code()`（映射协议错误码）；`init_tracing` 输出结构化 JSON（含 `trace_id` 支持）。

### T-03 tunnel-config：bootstrap 配置
- **目标**：Server/Agent 的 TOML 启动配置结构 + 校验（对应设计文档 §44/§45/§160）。
- **验收**：字段覆盖 §160；非法值（负端口、空 endpoints）返回 `Err`；有单测。

### T-04 tunnel-db：迁移与连接池
- **目标**：落地 `docs/schema.md` 的迁移（`0001_initial.sql`、`0002_traffic_stats.sql`），SQLx pool + `migrate`。
- **关键点**：用 `sqlx::migrate!()` embed；SQLite 与 PG 都能跑（类型见 schema.md）。
- **验收**：`cargo sqlx migrate run`（SQLite）成功；`Db` 有 `connect(url)`；迁移往返一致（migrate → 表存在）。

---

## M1 — 协议

### T-05 tunnel-protocol：帧编解码
- **目标**：实现 `docs/protocol.md` 的帧格式 + 全消息目录 encode/decode。
- **关键点**：大端；`length` 语义见 protocol.md；非法长度/未知类型 → `Err`（不 panic）。
- **验收**：全消息 roundtrip 单测；畸形输入（截断、超长 length、未知 type）→ `Err`；`#[cfg(fuzzing)]` 入口可被 cargo-fuzz 调用。

### T-06 协议 fuzz 骨架
- **目标**：`fuzz/` 目录，对 `decode_frame` 做 fuzz。
- **验收**：`cargo fuzz run frame_decode` 可跑；README 记录命令。

---

## M2 — Server 连接与认证

### T-07 Server QUIC listener
- **目标**：`server` 启动 `quinn::Endpoint`（UDP 443），接受连接，识别控制流。
- **验收**：集成测试能建立 QUIC 连接并打开控制流。

### T-08 认证（HELLO → AUTH → AUTH_OK）
- **目标**：token 认证流程，校验凭据 hash、revoked/expired/disabled，返回 AUTH_OK/AUTH_FAIL。
- **依赖**：M1。
- **验收**：正确 token → AUTH_OK（含 node_id、config_version）；错误/吊销/过期 token → AUTH_FAIL 对应错误码。

### T-09 Session Manager + Node 上线
- **目标**：`DashMap<NodeId, Arc<NodeSession>>`；节点上线/下线状态、`last_seen_at`、`connected_at` 持久化。
- **验收**：Agent 连上后 `GET /nodes`（或日志/状态）显示 online；断开后 offline；达到 §151 "Agent Online"。

---

## M3 — Agent 连接

### T-10 Agent QUIC 连接 + 认证
- **目标**：`agent` 读 bootstrap → 解析 endpoints → QUIC connect → 控制流 → HELLO/AUTH。
- **验收**：集成测试 Agent 连上 Server 并 AUTH_OK。

### T-11 心跳 PING/PONG + RTT
- **目标**：interval 15s / timeout 45s；记录 last_ping/last_pong/rtt。
- **验收**：超时判定离线；指标有 rtt。

### T-12 自动重连（指数退避 + jitter）
- **目标**：1/2/4/8/16/30/60s 封顶 + jitter；恢复后重新认证 + 配置同步。
- **验收**：杀 Server 后 Agent 自动重连上线；指标 `tunnel_agent_reconnect_total` 递增。

### T-13 配置接收与应用
- **目标**：处理 CONFIG_SNAPSHOT/CONFIG_UPDATE/CONFIG_ACK/CONFIG_RESYNC；写入本地运行时配置。
- **依赖**：M2（Server 需下发配置——可先下发空快照）。
- **验收**：Agent 收到快照并 ACK；版本不连续时发 RESYNC。

---

## M4 — TCP 隧道

### T-14 Server TCP Listener + Route 查找
- **目标**：按 Route 的 `listen_host:listen_port` 绑定；`listen → route` 查找；重复监听冲突校验。
- **验收**：客户端连 `server:port` 能匹配到 Route。

### T-15 数据面 OPEN_TCP / OPEN_OK / OPEN_FAIL
- **目标**：Server 开 bidi stream，正向 OPEN_TCP 帧 + 裸字节；Agent 侧 OPEN_OK/OPEN_FAIL 首帧；`copy_bidirectional`。
- **依赖**：M3。
- **验收**：`curl http://VPS:8080` 能访问内网服务（§152 第二阶段达成）。

### T-16 TCP half-close 与错误处理
- **目标**：正确处理 FIN/RST/EOF，支持 half-close（§109）；目标不可达 → OPEN_FAIL（TARGET_UNREACHABLE）。
- **验收**：半关闭场景不丢数据；目标离线返回明确错误码。

---

## M5 — 配置管理与热更新

### T-17 Config Manager（ArcSwap 快照）
- **目标**：`ArcSwap<ConfigSnapshot>`；`load → validate → atomic replace → broadcast`。
- **验收**：读端无锁；替换原子。

### T-18 配置版本与下发
- **目标**：Node `config_version += 1` 语义；CONFIG_UPDATE delta；ACK 处理；RESYNC 兜底。
- **依赖**：T-17。
- **验收**：改 Route → 对应 Node 版本 +1 → Agent ACK；Agent 离线时 `config_status=pending`。

### T-19 路由热更新（现有连接不断）
- **目标**：改 Route 不影响已建立连接；删 Route 走 draining（§139）。
- **验收**：改配置后现有 TCP 连接继续，新连接用新配置。

---

## M6 — REST API + Web UI

### T-20 Auth 与 Session（登录/登出/refresh/me）
- **目标**：Argon2id 密码校验、HttpOnly Secure SameSite cookie + 短 token、`/auth/*`。
- **依赖**：M2。
- **验收**：登录成功拿 cookie；错误密码 401；`/auth/me` 返回当前用户。

### T-21 Nodes / Routes CRUD + 校验
- **目标**：`/api/v1/nodes`、`/api/v1/routes` 全套；创建时走 §57 校验 + 审计日志。
- **依赖**：M5。
- **验收**：CRUD 通过 curl 走通；重复 listen/hostname 返回 409/422；每操作写 audit_logs。

### T-22 Credential 生成/吊销 + /enroll
- **目标**：`POST /nodes/:id/credentials`（token 只显示一次）、revoke、`POST /enroll`。
- **验收**：生成后仅一次返回明文，DB 存 hash；revoke 后 Agent 无法认证；bootstrap token 可 enroll。

### T-23 OpenAPI + 类型生成
- **目标**：`/openapi.json`、`/docs`；生成 TS 类型（供 Web）。
- **验收**：`/openapi.json` 可被 swagger 渲染；生成的 `Node/Route/User/...` 类型与 §132 一致。

### T-24 Web UI（登录/Node/Route 列表+表单）
- **目标**：`web/` 前端，登录、Node 列表、创建 Node、Route CRUD 页面。
- **验收**：§153 第三阶段达成——配置不再依赖 TOML。

### T-25 WebSocket 实时状态
- **目标**：`/ws` 推送 node/route/config/traffic 事件（§23）。
- **验收**：浏览器 dashboard 实时看到 node online/offline。

---

## M7 — HTTP / HTTPS / WebSocket

### T-26 HTTP Gateway（Host 路由）
- **目标**：`hyper`/`axum` 解析 Host → Route → 开流转发；注入/覆盖 `X-Forwarded-*`。
- **依赖**：M4。
- **验收**：`Host: app.example.com` 正确转发到目标；客户端伪造 XFF 被覆盖。

### T-27 TLS Termination + ACME
- **目标**：证书管理、Let's Encrypt/手动证书、TLS 终止后 HTTP/1.1 转 Agent。
- **验收**：HTTPS 访问 app.example.com 成功；证书过期告警。

### T-28 TLS Passthrough（SNI 路由）
- **目标**：按 SNI 选 Route，不解密透传。
- **验收**：直连目标 TLS 服务，Server 仅路由。

### T-29 WebSocket 隧道
- **目标**：识别 `Upgrade: websocket`，双向透传。
- **验收**：WebSocket 应用经隧道可用。

---

## M8 — UDP

### T-30 UDP Gateway（Datagram + 会话）
- **目标**：`(client_addr, route_id) → udp_session`；`UDP_OPEN/UDP_CLOSE`；QUIC Datagram 转发。
- **验收**：UDP 客户端经 Server→Agent 到内网 UDP 目标可用；超时会话回收。

### T-31 UDP 限速与反射防护
- **目标**：每源 IP 会话数/速率/字节限速；未建会话入向包丢弃。
- **验收**：伪造源地址不产生转发；超限被丢弃并计数。

### T-32 UDP 大包处理
- **目标**：`max_datagram_size`（默认 1200）判定，超限丢弃 + 计数（v1 不做分片）。
- **验收**：大包被明确丢弃并计数，不静默截断。

---

## M9 — 安全

### T-33 RBAC（角色 + 权限中间件）
- **目标**：admin/operator/viewer + 权限码；API 层强制校验（§31/§68）。
- **验收**：viewer 调写接口 → 403；admin 全通。

### T-34 ACL（数据面 + 管理面）
- **目标**：`acl_rules` 匹配（CIDR/port/hostname），默认 deny；Agent 本地 `allow/deny_targets`。
- **验收**：deny 的源被拒；Agent 拒绝未授权目标（含 loopback/link-local）。

### T-35 限速与防暴力破解
- **目标**：登录严格限速、管理 API 限速、Route/Node 连接限速。
- **验收**：连续失败登录触发 429/锁定；单 Route 超连接数被拒。

### T-36 审计完整性
- **目标**：§40 全事件写 audit_logs；审计查询 API。
- **验收**：CRUD/登录/凭据操作都可追溯。

### T-37 SSRF / 目标地址校验
- **目标**：目标地址拒绝 loopback/link-local/multicast/169.254.169.254（§106）。
- **验收**：配置到 169.254.169.254 被拒（除非管理员显式允许）。

---

## M10 — 运维

### T-38 Prometheus 指标
- **目标**：§38 指标全量暴露 `/metrics`（internal 端口）。
- **验收**：`curl 127.0.0.1:8080/metrics` 输出规范指标。

### T-39 健康检查 / 就绪
- **目标**：`/health`、`/ready`（§98 就绪条件）；Agent 本地 `/health`。
- **验收**：DB/QUIC/HTTP 未就绪时 `/ready` 返回非 200。

### T-40 Docker 镜像
- **目标**：`debian-slim`/distroless，非 root，端口映射见 §48。
- **验收**：`docker compose up` 起 Server + Agent + target，`curl` 走通。

### T-41 systemd 单元
- **目标**：server/agent 单元，Agent `Restart=always` + 沙箱（§49）。
- **验收**：`systemctl` 启动、开机自启、崩溃重启。

### T-42 备份/恢复
- **目标**：`tunnel-server` 备份命令/导出导入（§99/§100）；恢复演练。
- **验收**：备份 → 清库 → 恢复 → Agent 重连配置恢复。

---

## M11 — HA 与发布

### T-43 多 Server + Agent 多 endpoint 故障转移
- **目标**：`[[servers]]` 主备；Agent 主失败切备。
- **验收**：主 Server 停后 Agent 自动切到备。

### T-44 LB 会话亲和（QUIC Connection ID）
- **目标**：文档化 UDP 按 Connection ID 一致性哈希、TCP 源 IP 亲和（§50）。
- **验收**：LB 后连接不漂移（可集成测试/说明）。

### T-45 发布流水线
- **目标**：CI（fmt/clippy/test/build/audit/deny）+ 三平台产物 + Docker push（§124/§125）。
- **验收**：tag 触发发布，产物可用。

### T-46 压测与性能目标验证
- **目标**：1→10k Agent、1→10k 并发连接 benchmark（§149/§61）。
- **验收**：产出基准报告；满足 §61 目标或记录差距与瓶颈。

---

## 执行顺序建议（给 agent 的起手批次）

**第一批（可并行，无强依赖）**：T-01、T-05、T-03（骨架/协议/配置）。
**第二批**：T-02、T-04、T-06（common/db/fuzz）。
**第三批（主线）**：T-07 → T-08 → T-09 → T-10 → T-11 → T-12 → T-13 → T-14 → T-15 → T-16（跑通第一阶段 + TCP 隧道）。
之后按里程碑顺序推进，M6 起可与 M7/M8 并行。
