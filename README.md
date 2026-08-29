# Rust Tunnel

可自托管、可生产部署的内网穿透平台（Cloudflare Tunnel / FRP 类）。

- **Tunnel Server**：公网侧，接受 Agent 主动建立的 QUIC 连接，负责 HTTP/TCP/UDP 接入、路由、认证、API、Web 管理。
- **Tunnel Agent**：内网侧，主动出站连接 Server，把流量转发到内网目标。
- **Web 管理后台 + REST API + WebSocket**：控制面，配置持久化到数据库。

完整设计见 [`docs/rust-tunnel-design.md`](docs/rust-tunnel-design.md)。

## 文档索引

### 用户文档

| 文档 | 内容 |
|------|------|
| [quickstart.md](docs/quickstart.md) | 快速上手（5 分钟跑通第一个隧道） |
| [config-reference.md](docs/config-reference.md) | 配置参数详解（server/agent TOML 全字段 + 路由字段） |
| [comparison.md](docs/comparison.md) | 定位、优缺点与竞品对比（vs Cloudflare Tunnel / FRP / ngrok 等） |

### 开发者文档

| 文档 | 内容 |
|------|------|
| [rust-tunnel-design.md](docs/rust-tunnel-design.md) | 产品级设计（架构/组件/原则/DoD） |
| [plan.md](docs/plan.md) | 分阶段开发计划与任务验收标准 |
| [protocol.md](docs/protocol.md) | 控制协议与数据面 wire 格式 |
| [schema.md](docs/schema.md) | 数据库迁移与索引 |
| [api.md](docs/api.md) | REST + WebSocket 契约 |
| [architecture.md](docs/architecture.md) | crate 职责、核心 trait、数据流 |
| [lb-session-affinity.md](docs/lb-session-affinity.md) | 多 Server 前置 LB 的会话亲和（QUIC/UDP/TCP）与验证 |
| [benchmark.md](docs/benchmark.md) | 性能基准（T-46）：1→10k Agent / 并发连接实测与瓶颈 |
| [AGENTS.md](AGENTS.md) | 开发约定与单任务 DoD |

## 技术栈

Rust + Tokio + Quinn(QUIC) + Rustls(TLS 1.3) + Axum(HTTP API) + SQLx(SQLite/PostgreSQL) + Tracing + Prometheus。

## 快速开始

> 更完整的从零上手（含配置模板、生产部署要点、常见坑排查）见 [`docs/quickstart.md`](docs/quickstart.md)。

### 方式一：Docker 演示（一键走通）

```bash
# 仓库根目录
docker compose -f deploy/docker/docker-compose.yml up --build
```

拓扑为 `server + agent + target`；server 启动时经 `[demo]` 配置段自动种入演示 Node + 凭据 + 一条 HTTP Route。走通验证（HTTP 隧道按 Host 路由到 target）：

```bash
curl -H "Host: app.example.com" http://localhost:8080/
```

管理面（容器内回环，未对外发布）：Web 管理后台 `http://127.0.0.1:8080/`（首次打开会先引导创建管理员账户），以及 `http://127.0.0.1:8080/health`、`/ready`、`/metrics`、`/docs`（Swagger UI）。

### 方式二：本地开发

```bash
# 构建两个二进制
cargo build -p tunnel-server -p tunnel-agent
```

1. 准备配置文件：以 [`deploy/docker/config/server.toml`](deploy/docker/config/server.toml) 与 [`agent.toml`](deploy/docker/config/agent.toml) 为模板，改成本地地址（如 server `[internal].bind`/`[database].url`，agent `[[servers]].address` → `127.0.0.1:443`；`[server].ca` 可省略——缺省时 Agent 首次连接自动信任并固定服务端证书（TOFU），无需手动拷贝证书）。

2. 启动 server（自动建库 + 迁移 + 生成自签名证书）：

```bash
./target/debug/tunnel-server --config server.toml
```

3. 建 Node 并签发凭据：浏览器打开 `http://127.0.0.1:8080/`（首次会引导创建管理员账户），在 Web 后台建一个 Node，再签发运行时 token（明文仅显示一次，库中只存 SHA-256），最后建一条 Route 指向内网目标。把签发的 token 填入 `agent.toml` 的 `[auth].token`。

> 只想快速走通？在 `server.toml` 加一段 `[demo]`（`enabled = true`、`token = "<明文 token>"`），server 启动时自动种入 `demo-node` + 凭据 + 一条 `Host: app.example.com` 的 HTTP Route；`agent.toml` 的 `[auth].token` 填同一 token，即可跳过本步。

4. 启动 agent（`[auth].token` 与第 3 步一致）：

```bash
./target/debug/tunnel-agent --config agent.toml
```

5. 走通验证：

```bash
curl -H "Host: app.example.com" http://127.0.0.1:8080/
```

## 使用说明

### 两个二进制

| 二进制 | 作用 | 入口 |
|--------|------|------|
| `tunnel-server` | 公网侧：QUIC 接入 + HTTP/TCP/UDP 转发 + 认证 + REST API + 备份/导入导出 | `--config server.toml`（默认 `config/server.toml`） |
| `tunnel-agent` | 内网侧：主动出站 QUIC，把流量转发到内网目标 | `--config agent.toml`（默认 `config/agent.toml`） |

> 两个二进制均只走一个入口，启动时会自动跑数据库迁移，无需单独的 migrate 步骤。原 `tunnel-cli` 的运维能力（token/密码哈希生成、演示种入、备份/恢复、配置导入导出）已并入 server 的 Web 后台与 REST API。

### 配置文件

> 每个字段的类型、默认值与含义（含 `[[servers]]`、SSRF 策略判定规则、Route 字段与 `limits` 限速）见 [`docs/config-reference.md`](docs/config-reference.md)。

- **Server**（示例 [`deploy/docker/config/server.toml`](deploy/docker/config/server.toml)）
  - `[http].bind` / `[https].bind`：HTTP / HTTPS 隧道入口
  - `[quic].bind`：Agent QUIC 接入（UDP）
  - `[internal].bind`：管理面 REST API + `/metrics` `/health` `/ready`（生产只绑定回环）
  - `[internal].web_dir`：Web 管理后台静态目录（`web/dist` 构建产物）；配置后 `/` 即同源托管 SPA，否则仅 API/Swagger（前端需另跑 `vite`）
  - `[database].url`：SQLite / PostgreSQL 连接串
  - `[tls].subjects`：自签名证书 SAN；`[tls].cert_der_path`/`key_der_path`：证书与私钥 DER 落盘路径（同时配置后跨重启复用同一证书，否则每次启动新生成）
  - `[security]`：登录限速、`allow_unsafe_targets`（SSRF 目标校验开关）
- **Agent**（示例 [`deploy/docker/config/agent.toml`](deploy/docker/config/agent.toml)）
  - `[[servers]].address`：server QUIC 地址（多条 = 故障转移，primary 在前）
  - `[server].ca`：显式信任 server 的证书/CA DER（可选）。缺省时 Agent 走 TOFU：首次连接信任并固定服务端证书到 `<data.directory>/server-pins/`，之后每次严格校验（证书变更即拒绝，防中间人）
  - `[auth].token`：agent 运行时 token
  - `[data].directory`、`[health].bind`（默认 `127.0.0.1:9090/health`）、`[security].allow/deny_targets`

### 管理面 API

server 在 `[internal].bind`（示例 `127.0.0.1:8080`）提供：

| 端点 | 说明 |
|------|------|
| `GET /health` `GET /ready` | 存活 / 就绪探针 |
| `GET /metrics` | Prometheus 指标 |
| `GET /` | Web 管理后台 SPA（需 `[internal].web_dir`；同源调用下方 API/WS） |
| `GET /docs` | Swagger UI（`/openapi.json` 为原始 OpenAPI 文档） |
| `GET /ws` | WebSocket（订阅 node/route/config 事件） |
| `POST /auth/login` `/logout` `/refresh`，`GET /auth/me` | 会话认证（HttpOnly cookie + 短时 Bearer） |
| `GET/POST /api/v1/setup` | 首次引导：`users` 表为空时创建初始 admin（创建后自锁 409） |
| `POST /enroll` | Agent 用 bootstrap token 换取运行时凭据（一次性） |
| `/api/v1/nodes` `/api/v1/routes`（CRUD） | Node / Route 管理 |
| `POST /api/v1/nodes/:id/credentials` | 给 Node 签发凭据（`type=token` 或 `bootstrap`） |
| `/api/v1/acl` `/api/v1/audit` | ACL 规则、审计日志 |

> 管理端点（`/api/v1/*`）需要登录：先 `POST /auth/login` 拿 session cookie，或带 `Authorization: Bearer <access_token>`。唯一例外是 `/api/v1/setup`（首次引导，仅在 `users` 表为空时开放）。完整契约见 [`docs/api.md`](docs/api.md)。

### 路由类型

| 类型 | 匹配方式 | 典型用途 |
|------|----------|----------|
| `http` | 按 `Host` 头路由，经 agent 透传到内网目标，注入 `X-Forwarded-*` | Web 服务 |
| `https` | 按 SNI 终止 TLS（手动证书），解密后复用 HTTP 数据面 | 带证书的 Web 服务 |
| `tcp` | server 按 Route 绑定监听端口，经 QUIC 透传到内网 | 数据库 / 任意 TCP |
| `udp` | server 按 Route 绑定 UDP 监听，datagram ↔ QUIC datagram | DNS / 游戏等 |

## Fuzz（协议健壮性）

对帧/消息解码做 libFuzzer 模糊测试（需 nightly + `cargo-fuzz`）：

```bash
cargo install cargo-fuzz
cargo fuzz run frame_decode    # Frame::try_decode 对任意字节不 panic
cargo fuzz run message_decode  # Message::from_frame 对任意字节不 panic
```

## 目录

见 [`AGENTS.md`](AGENTS.md) 第 1 节。

## License

（待定）
