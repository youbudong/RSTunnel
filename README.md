# Rust Tunnel

可自托管、可生产部署的内网穿透平台（Cloudflare Tunnel / FRP 类）。

- **Tunnel Server**：公网侧，接受 Agent 主动建立的 QUIC 连接，负责 HTTP/TCP/UDP 接入、路由、认证、API、Web 管理。
- **Tunnel Agent**：内网侧，主动出站连接 Server，把流量转发到内网目标。
- **Web 管理后台 + REST API + WebSocket**：控制面，配置持久化到数据库。

完整设计见 [`docs/rust-tunnel-design.md`](docs/rust-tunnel-design.md)。

## 文档索引

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

### 方式一：Docker 演示（一键走通）

```bash
# 仓库根目录
docker compose -f deploy/docker/docker-compose.yml up --build
```

拓扑为 `server + agent + target + init`；`init` 一次性服务用 `tunnel-cli seed` 种入演示 Node + 凭据 + 一条 HTTP Route。走通验证（HTTP 隧道按 Host 路由到 target）：

```bash
curl -H "Host: app.example.com" http://localhost:8080/
```

管理面（容器内回环，未对外发布）：`http://127.0.0.1:8080/health`、`/ready`、`/metrics`、`/docs`（Swagger UI）。

### 方式二：本地开发

```bash
# 构建三个二进制
cargo build -p tunnel-server -p tunnel-agent -p tunnel-cli

# 生成一个 agent 运行时 token（明文仅显示一次）
./target/debug/tunnel-cli token
```

1. 准备配置文件：以 [`deploy/docker/config/server.toml`](deploy/docker/config/server.toml) 与 [`agent.toml`](deploy/docker/config/agent.toml) 为模板，改成本地地址（如 server `[internal].bind`/`[database].url`，agent `[[servers]].address` → `127.0.0.1:443`、`[server].ca` → server 落盘的证书 DER）。
2. 种入一个演示节点 + 路由（`<TOKEN>` 换成上一步生成的 token）：

```bash
./target/debug/tunnel-cli seed \
  --db sqlite://data/tunnel.db \
  --token <TOKEN> \
  --target-host 127.0.0.1 --target-port 5678 \
  --hostname app.example.com
```

3. 启动 server（自动建库 + 迁移 + 生成自签名证书）：

```bash
./target/debug/tunnel-server --config server.toml
```

4. 启动 agent（`[auth].token` 与第 2 步一致）：

```bash
./target/debug/tunnel-agent --config agent.toml
```

5. 走通验证：

```bash
curl -H "Host: app.example.com" http://127.0.0.1:8080/
```

## 使用说明

### 三个二进制

| 二进制 | 作用 | 入口 |
|--------|------|------|
| `tunnel-server` | 公网侧：QUIC 接入 + HTTP/TCP/UDP 转发 + 认证 + REST API | `--config server.toml`（默认 `config/server.toml`） |
| `tunnel-agent` | 内网侧：主动出站 QUIC，把流量转发到内网目标 | `--config agent.toml`（默认 `config/agent.toml`） |
| `tunnel-cli` | 管理引导：token/密码哈希生成、演示种入、备份/恢复、配置导入导出 | 子命令见下 |

> 三个二进制均只走一个入口，启动时会自动跑数据库迁移，无需单独的 migrate 步骤。

### tunnel-cli 子命令

| 子命令 | 说明 |
|--------|------|
| `token` | 生成 agent 运行时 token（明文仅显示一次，库中只存 SHA-256） |
| `hash-password <pwd>` | 生成 Argon2id 密码哈希（用于管理员用户） |
| `seed --db <url> --token <T> [--target-host H] [--target-port P] [--hostname D]` | 种入演示 Node `demo-node` + 凭据 + 一条 HTTP Route（幂等） |
| `backup --db <url> [--output F]` | 全量备份（含凭据哈希与证书）到 YAML |
| `restore --db <url> --input F [--yes]` | 从全量备份恢复（缺省预览，加 `--yes` 落库） |
| `export --db <url> [--output F]` | 导出控制面配置（不含凭据/证书） |
| `import --db <url> --input F [--yes]` | 导入控制面配置（缺省预览；拒绝含凭据的备份文件） |

### 配置文件

- **Server**（示例 [`deploy/docker/config/server.toml`](deploy/docker/config/server.toml)）
  - `[http].bind` / `[https].bind`：HTTP / HTTPS 隧道入口
  - `[quic].bind`：Agent QUIC 接入（UDP）
  - `[internal].bind`：管理面 REST API + `/metrics` `/health` `/ready`（生产只绑定回环）
  - `[database].url`：SQLite / PostgreSQL 连接串
  - `[tls].subjects`：自签名证书 SAN；`[tls].cert_der_path`：证书 DER 落盘路径（供 agent 信任）
  - `[security]`：登录限速、`allow_unsafe_targets`（SSRF 目标校验开关）
- **Agent**（示例 [`deploy/docker/config/agent.toml`](deploy/docker/config/agent.toml)）
  - `[[servers]].address`：server QUIC 地址（多条 = 故障转移，primary 在前）
  - `[server].ca`：信任 server 的证书 DER（自签名时必填）
  - `[auth].token`：agent 运行时 token
  - `[data].directory`、`[health].bind`（默认 `127.0.0.1:9090/health`）、`[security].allow/deny_targets`

### 管理面 API

server 在 `[internal].bind`（示例 `127.0.0.1:8080`）提供：

| 端点 | 说明 |
|------|------|
| `GET /health` `GET /ready` | 存活 / 就绪探针 |
| `GET /metrics` | Prometheus 指标 |
| `GET /docs` | Swagger UI（`/openapi.json` 为原始 OpenAPI 文档） |
| `GET /ws` | WebSocket（订阅 node/route/config 事件） |
| `POST /auth/login` `/logout` `/refresh`，`GET /auth/me` | 会话认证（HttpOnly cookie + 短时 Bearer） |
| `POST /enroll` | Agent 用 bootstrap token 换取运行时凭据（一次性） |
| `/api/v1/nodes` `/api/v1/routes`（CRUD） | Node / Route 管理 |
| `POST /api/v1/nodes/:id/credentials` | 给 Node 签发凭据（`type=token` 或 `bootstrap`） |
| `/api/v1/acl` `/api/v1/audit` | ACL 规则、审计日志 |

> 管理端点（`/api/v1/*`）需要登录：先 `POST /auth/login` 拿 session cookie，或带 `Authorization: Bearer <access_token>`。完整契约见 [`docs/api.md`](docs/api.md)。

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
