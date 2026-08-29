# 配置参数详解

RSTunnel 有两类配置，别混淆：

1. **Bootstrap 配置**（本文件）：`server.toml` / `agent.toml`，定义「进程怎么启动、连哪、绑哪个端口」。
2. **业务路由（Route）**：存在数据库里，通过 Web 管理后台 / REST API 增删改，定义「哪个域名/端口转发到内网哪个目标」。字段见文末「[路由（Route）字段](#路由route-字段)」。

TOML 中未写的字段会取默认值（下表「默认」列）。`server.toml`/`agent.toml` 的完整可运行示例见 [`deploy/docker/config/`](../deploy/docker/config/)。

---

## Server 配置（server.toml）

### `[http]` — HTTP 隧道入口

| 字段 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `bind` | string | `0.0.0.0:443` | HTTP 隧道监听地址。按 `Host` 头路由到 `http`/`https` 路由 |

> ⚠️ 注意：`[http].bind` 与 `[https].bind` **默认都是 `0.0.0.0:443`**。生产务必至少改一个（通常 http 用 80、https 用 443），否则会端口冲突。

### `[https]` — HTTPS 入口（TLS 终止 / 透传）

| 字段 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `bind` | string | `0.0.0.0:443` | HTTPS 监听地址。按 SNI 选证书终止，或匹配 `passthrough` 路由透传 |

### `[quic]` — Agent 接入（QUIC/UDP）

| 字段 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `bind` | string | `0.0.0.0:443` | QUIC UDP 监听地址（Agent 主动出站连这里） |
| `max_concurrent_bidi_streams` | u64 | `10000` | 单连接最大并发双向流 |
| `max_concurrent_uni_streams` | u64 | `1000` | 单连接最大并发单向流 |
| `idle_timeout_seconds` | u64 | `60` | QUIC 连接空闲超时（秒） |

> `[quic].bind`（UDP 443）与 `[https].bind`（TCP 443）可同用 443 端口——协议不同，互不影响。

### `[internal]` — 管理面

| 字段 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `bind` | string | `127.0.0.1:8080` | REST API + Swagger + `/metrics` `/health` `/ready`。生产只绑回环 |
| `web_dir` | string? | 无 | Web 管理后台静态目录（`web/dist`）。配置后 `/` 同源托管 SPA；缺省仅 API/Swagger |

### `[database]` — 数据库

| 字段 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `url` | string | `sqlite://tunnel.db` | SQLite 连接串（PostgreSQL 在 HA 里程碑启用） |

### `[logging]` — 日志

| 字段 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `level` | string | `info` | 日志级别（`trace`/`debug`/`info`/`warn`/`error`）。排查路由匹配类问题临时开 `debug` 能看到 `no route for host` / `tls handshake failed` 等 |

### `[security]` — Server 安全

| 字段 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `max_login_attempts` | u32 | `5` | 窗口内连续失败达到该次数后锁定该用户名（登录返回 429） |
| `login_window_seconds` | u64 | `300` | 登录失败统计窗口（秒） |
| `allow_unsafe_targets` | bool | `false` | `true` 时跳过 SSRF 目标校验，允许 Route 目标指向 loopback/link-local/metadata 等危险地址 |

### `[tls]` — Server 自签证书（开发/演示；生产 HTTPS 证书走 Route/T-27）

| 字段 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `subjects` | string[] | `["localhost"]` | 自签证书 SAN，须包含 Agent 连接所用的主机名，否则握手失败 |
| `cert_der_path` | string? | 无 | 证书 DER 落盘路径（供 Agent 作为 `[server].ca` 信任） |
| `key_der_path` | string? | 无 | 私钥 DER 落盘路径。与 `cert_der_path` **同时**配置时跨重启复用同一证书；缺省每次启动新生成 |

### `[demo]` — 演示引导（替代原 tunnel-cli seed）

| 字段 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `enabled` | bool | `false` | 开启后 server 启动时在库为空时种入 `demo-node` + 凭据 + 一条 HTTP Route（幂等）。生产删除本节或设 `false` |
| `token` | string | `""` | 演示 Agent 的运行时 token（`enabled` 时必填，与 `[auth].token` 一致） |
| `hostname` | string | `app.example.com` | 演示 Route 的 Host |
| `target_host` | string | `target` | 演示 Route 的内网目标主机 |
| `target_port` | u16 | `5678` | 演示 Route 的内网目标端口 |

---

## Agent 配置（agent.toml）

### `[[servers]]` — Server 列表（故障转移）

| 字段 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `address` | string | — | Server QUIC 地址 `host:port`。数组顺序即优先级（首个 primary，其后 fallback） |

> 配置了 `[[servers]]` 时，旧的 `[server].endpoints` 会被忽略。

### `[server]` — （旧式）端点与证书信任

| 字段 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `endpoints` | string[] | `[]` | 旧式平铺端点列表（向后兼容；`[[servers]]` 存在时被忽略） |
| `ca` | string? | 无 | 显式信任的 Server 证书/CA（DER）。缺省走 TOFU：首次连接信任并固定 Server 证书到 `<data.directory>/server-pins/`，之后证书变更即拒绝（防中间人） |

### `[auth]` — 凭据

| 字段 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `token` | string | —（必填） | Agent 运行时 token（Web 后台 / `POST /api/v1/nodes/:id/credentials` 签发；库中只存 SHA-256） |

### `[agent]` — 元信息

| 字段 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `name` | string | `agent` | Agent 显示名 |

### `[data]` — 持久化目录

| 字段 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `directory` | string | `/var/lib/tunnel-agent` | 证书 pin、运行时状态等落盘目录 |

### `[health]` — 本地健康探针

| 字段 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `bind` | string | `127.0.0.1:9090` | 健康探针地址，`GET /health` 返回 `{"status":"ok"}`（供编排器/`systemctl` 探活） |

### `[security]` — Agent 出站目标安全策略（SSRF 防护）

| 字段 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `allow_targets` | string[]（CIDR） | `[]` | 白名单。非空时仅这些目标放行；显式允许优先于 deny |
| `deny_targets` | string[]（CIDR） | `["127.0.0.0/8","169.254.0.0/16"]` | 黑名单。默认拒绝 loopback 与 link-local |

判定规则（`allow` 优先）：

```text
allow_targets 非空
  ├─ 命中 allow  → 放行（即使也在 deny）
  ├─ 未命中 allow → 拒绝
  └─ （allow 为空）→ 命中 deny 即拒绝，否则放行
```

> 目标为域名时 Agent 先 DNS 解析，再按解析出的 IP 校验（直连 IP 连接，避免 DNS 重绑绕过）。

---

## 路由（Route）字段

Route 存在数据库，由 Web 后台 / REST API 管理（`/api/v1/routes`）。字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | string | 路由名（唯一） |
| `node_id` | UUID | 归属的 Node（Agent） |
| `type` | enum | `tcp` / `udp` / `http` / `https` |
| `enabled` | bool | 是否启用（禁用即从数据面移除） |
| `target_host` | string | 内网目标主机（Agent 视角可达的 IP 或域名） |
| `target_port` | u16 | 内网目标端口 |
| `hostname` | string? | 仅 `http`/`https`：用于 Host/SNI 匹配的域名（小写归一化） |
| `listen_host` | string? | 仅 `tcp`/`udp`：Server 监听 IP（默认 `0.0.0.0`） |
| `listen_port` | u16? | 仅 `tcp`/`udp`：Server 监听端口（必填） |
| `tls_mode` | enum | `disabled` / `terminate` / `passthrough`（见下） |
| `limits` | object? | 限速（见下） |

### 四种类型

| 类型 | 匹配方式 | 典型用途 |
|------|----------|----------|
| `http` | 按 `Host` 头路由，注入 `X-Forwarded-*`，经 Agent 透传 | 明文 Web 服务 |
| `https` + `terminate` | 按 SNI 终止 TLS（需证书库里有该 hostname 的证书），解密后复用 HTTP 数据面 | 有证书的 Web 服务 |
| `https` + `passthrough` | 按 SNI 路由但不解密，Agent 把原始 TLS 透传给目标（目标自己持证书） | 目标自持 TLS |
| `tcp` | Server 按 `listen_host:listen_port` 绑定，经 QUIC 透传 | 数据库 / 任意 TCP |
| `udp` | Server 绑定 UDP，datagram ↔ QUIC datagram | DNS / 游戏等 |

### `limits` 限速

| 字段 | 类型 | 说明 |
|------|------|------|
| `max_connections` | u64? | 单 Route 最大并发连接数（超限返回 429） |
| `max_connection_rate` | u64? | 新建连接速率上限 |
| `max_bandwidth` | u64? | 带宽上限 |

---

## 完整示例

```toml
# server.toml
[http]
bind = "0.0.0.0:80"

[https]
bind = "0.0.0.0:443"

[quic]
bind = "0.0.0.0:443"
max_concurrent_bidi_streams = 10000
max_concurrent_uni_streams = 1000
idle_timeout_seconds = 60

[internal]
bind = "127.0.0.1:8080"
web_dir = "/app/web/dist"

[database]
url = "sqlite:///data/tunnel.db"

[logging]
level = "info"

[security]
max_login_attempts = 5
login_window_seconds = 300
allow_unsafe_targets = false

[tls]
subjects = ["tunnel.example.com", "localhost"]
cert_der_path = "/etc/tunnel/certs/server.der"
key_der_path = "/etc/tunnel/certs/server.key.der"
```

```toml
# agent.toml
[[servers]]
address = "tunnel.example.com:443"

[server]
# ca = "/etc/tunnel/certs/server.der"   # 可选：显式信任；缺省走 TOFU 自动 pin

[auth]
token = "<Web 后台 / API 签发的 token>"

[agent]
name = "home-nas"

[data]
directory = "/var/lib/tunnel-agent"

[health]
bind = "127.0.0.1:9090"

[security]
allow_targets = ["192.168.1.0/24"]
# deny_targets 缺省即拒绝 127.0.0.0/8 与 169.254.0.0/16
```
