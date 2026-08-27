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

## 快速开始（开发）

```bash
# 构建全部二进制
cargo build -p tunnel-server -p tunnel-agent -p tunnel-cli

# 初始化数据库并迁移（SQLite）
export DATABASE_URL="sqlite://tunnel.db"
cargo sqlx migrate run

# 启动 Server（初始化生成 admin/证书/secret）
cargo run -p tunnel-server -- init
cargo run -p tunnel-server -- start

# 启动 Agent（需先在 Web 创建 Node 并生成凭据）
cargo run -p tunnel-agent -- run
```

Docker：

```bash
docker compose -f deploy/docker/docker-compose.yml up
```

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
