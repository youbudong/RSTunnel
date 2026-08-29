# 快速上手

> 5 分钟把第一个内网服务暴露到公网。完整参数见 [`config-reference.md`](config-reference.md)，定位与竞品对比见 [`comparison.md`](comparison.md)。

## 架构一句话

```text
公网请求 ──> Server（公网，QUIC 接入 + HTTP/TCP/UDP 转发）
                    ▲
                    │ Agent 主动出站建立 QUIC（无需公网 IP / 无需开放入站端口）
                    │
                 Agent（内网）──> 内网目标服务（web / db / 任意 TCP / UDP）
```

- **Server** 跑在有一台公网 IP/域名的机器上，负责对外接受流量、认证、路由。
- **Agent** 跑在内网、靠近目标服务，主动出站连 Server（所以内网无需公网 IP，也不用开防火墙入站规则）。
- **路由（Route）** 存在数据库里，通过 Web 管理后台或 REST API 配置。

## 前置条件

- 一台有公网 IP（或已解析域名）的 Linux 服务器跑 Server。
- 内网机器跑 Agent（能出站访问 Server 的 QUIC 端口）。
- 构建方式二选一：源码需 Rust 1.88+；或直接用 Docker。

---

## 方式一：Docker 一键（最快验证）

仓库内置了一个 `server + agent + target` 的演示拓扑：

```bash
docker compose -f deploy/docker/docker-compose.yml up --build
```

server 启动时经 `[demo]` 配置段自动种入演示 Node + 凭据 + 一条 `Host: app.example.com` 的 HTTP 路由。走通验证：

```bash
curl -H "Host: app.example.com" http://localhost:8080/
# => hello from target
```

管理面（容器内回环）：Web 后台 `http://127.0.0.1:8080/`（首次打开会引导创建管理员账户）、`/health`、`/ready`、`/metrics`、`/docs`（Swagger UI）。

---

## 方式二：本地二进制（源码构建）

```bash
cargo build -p tunnel-server -p tunnel-agent
```

### 1. 写 `server.toml`

```toml
[http]
bind = "0.0.0.0:80"           # HTTP 隧道入口（按 Host 路由）

[https]
bind = "0.0.0.0:443"          # HTTPS 入口（TLS 终止 / 透传）

[quic]
bind = "0.0.0.0:443"          # Agent QUIC 接入（UDP，与上面 TCP 443 不冲突）

[internal]
bind = "127.0.0.1:8080"       # 管理面（REST/Web/Swagger），生产只绑回环
# web_dir = "/app/web/dist"   # 可选：同源托管 Web 管理后台静态目录

[database]
url = "sqlite://data/tunnel.db"

[logging]
level = "info"

[tls]
subjects = ["your-server.example.com"]  # 自签名证书 SAN，须含 Agent 连接用的主机名

# 只想快速走通可加一段 [demo]，启动时自动种入 demo-node + 凭据 + 一条 HTTP Route：
# [demo]
# enabled = true
# token = "<明文 token>"
# hostname = "app.example.com"
# target_host = "127.0.0.1"
# target_port = 5678
```

### 2. 写 `agent.toml`

```toml
[[servers]]
address = "your-server.example.com:443"   # Server 的 QUIC 地址；多条 = 故障转移

[auth]
token = "<Web 后台 / API 签发的 token>"

[agent]
name = "my-agent"

[data]
directory = "/var/lib/tunnel-agent"

[health]
bind = "127.0.0.1:9090"

# [security] 默认已拒绝 loopback/link-local 目标（防 SSRF），见 config-reference.md
```

### 3. 启动 server，用 Web 后台建 Node 并签发凭据

```bash
./target/debug/tunnel-server --config server.toml   # 自动建库 + 迁移 + 生成自签证书
```

浏览器打开 `http://127.0.0.1:8080/`（首次会引导创建管理员账户）：建一个 Node，
`POST /api/v1/nodes/:id/credentials` 签发运行时 token（明文仅显示一次，库中只存
SHA-256），再建一条 Route 指向内网目标。把签发的 token 填入第 2 步的 `[auth].token`。

> 若第 1 步开了 `[demo]`，则 server 已自动种入 `demo-node` + 凭据 + 一条
> `Host: app.example.com` 的 HTTP Route，可直接跳过本步（token 用 `[demo].token`）。

### 4. 启动 agent

```bash
./target/debug/tunnel-agent --config agent.toml
```

### 5. 验证

```bash
curl -H "Host: app.example.com" http://127.0.0.1:8080/
```

---

## 方式三：生产部署要点

1. **域名解析**：把要暴露的域名 A 记录指到 Server 公网 IP。⚠️ 若用 Cloudflare，把记录设为 **DNS only（灰色云）**，不要开橙色云代理——它只代理 80/443 等白名单端口，且会劫持流量导致「加载中/503」这类假故障。
2. **端口**：对外至少放开 Server 的 `[http].bind` / `[https].bind`（TCP）与 `[quic].bind`（UDP）。
3. **证书**：生产用 HTTPS 时，要么给 `https` 路由配证书（TLS 终止），要么 `tls_mode=passthrough` 透传给内网自己持有证书的服务。`[tls].cert_der_path`/`key_der_path` 同时配置可让 Server 跨重启复用同一张自签证书。
4. **systemd**：参考 [`deploy/systemd/`](../deploy/systemd/) 的 unit 与配置模板。
5. **登录**：`/api/v1/setup` 首次引导创建管理员（`users` 表为空时开放，之后自锁）。

---

## 常见坑（先看这里）

| 现象 | 原因 | 解决 |
|------|------|------|
| 一直转圈 / 503，Server 无日志 | Cloudflare 橙色云劫持、或域名没指到 Server | 改 DNS only，`dig` 确认解析 |
| 一直转圈，无日志 | `https://` 打到了 `http` 路由（无证书，TLS 握手静默失败） | 用 `http://` 访问，或建 `https` 路由 + 证书 |
| agent 日志 `target denied` | 路由 target 是 `127.0.0.1` 等，被 agent SSRF 策略拦截 | target 改内网 IP，或 agent `[security]` 放行 |
| `no route for host`（debug） | Host 头和 route 的 hostname 对不上 / 路由没生效 | 检查 hostname 大小写、以及 server 是否已热加载（v0.2.6+） |
| 证书握手失败 | 自签证书 SAN 不含 Agent 连接用的主机名 | 改 `[tls].subjects`，或让 Agent 显式信任 `[server].ca` |

## 下一步

- 全部配置项 → [`config-reference.md`](config-reference.md)
- 和 Cloudflare Tunnel / FRP / ngrok 等的对比与选型 → [`comparison.md`](comparison.md)
- 架构与设计 → [`rust-tunnel-design.md`](rust-tunnel-design.md)
