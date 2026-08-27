# 数据库迁移与索引

> 本文是设计文档 §19/§20 的可落地版本。迁移文件放在 `migrations/`，由 `tunnel-db` 用 `sqlx::migrate!()` embed。
> **可移植类型约定**（SQLite 与 PostgreSQL 通用）：
> - 主键/外键：`TEXT`，存 UUID v4 字符串（应用层 `uuid` crate 生成）。
> - 时间戳：`TEXT`，RFC3339 / ISO-8601 UTC（如 `2026-08-27T12:00:00Z`）。
> - 布尔：`BOOLEAN`（SQLite 下存 0/1，SQLx 自动映射 `bool`）。
> - JSON：`TEXT`，存 JSON 字符串（应用层 `serde_json`）。
>
> 若 PostgreSQL 部署希望用原生 `UUID`/`TIMESTAMPTZ`/`JSONB`，另维护一套 PG 专属迁移，v1 不强制。

---

## migrations/0001_initial.sql

```sql
-- users
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

-- roles
CREATE TABLE roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT
);

-- user_roles
CREATE TABLE user_roles (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- nodes
CREATE TABLE nodes (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
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

-- credentials
CREATE TABLE credentials (
    id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    type TEXT NOT NULL,                -- 'bootstrap' | 'token' | 'mtls'
    secret_hash TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT,
    last_used_at TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_credentials_node ON credentials(node_id);
CREATE INDEX idx_credentials_hash ON credentials(secret_hash);

-- routes
CREATE TABLE routes (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    name TEXT NOT NULL UNIQUE,
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    type TEXT NOT NULL,                -- 'tcp' | 'udp' | 'http' | 'https'
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    listen_host TEXT,
    listen_port INTEGER,
    hostname TEXT,
    target_host TEXT NOT NULL,
    target_port INTEGER NOT NULL,
    tls_mode TEXT,                     -- 'terminate' | 'passthrough' | 'disabled'
    status TEXT NOT NULL DEFAULT 'draft',
    limits TEXT,                       -- JSON: max_connections/max_connection_rate/max_bandwidth
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX idx_routes_node ON routes(node_id);
CREATE INDEX idx_routes_hostname ON routes(hostname);

-- acl_rules
CREATE TABLE acl_rules (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    route_id TEXT REFERENCES routes(id) ON DELETE CASCADE,
    action TEXT NOT NULL,              -- 'allow' | 'deny'
    source_cidr TEXT,
    source_port INTEGER,
    target_host TEXT,
    target_port INTEGER,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_acl_route ON acl_rules(route_id);

-- domains
CREATE TABLE domains (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    hostname TEXT NOT NULL UNIQUE,
    route_id TEXT REFERENCES routes(id) ON DELETE SET NULL,
    tls_mode TEXT,
    certificate_id TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- certificates
CREATE TABLE certificates (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    name TEXT NOT NULL,
    hostnames TEXT NOT NULL,           -- JSON 数组
    certificate TEXT NOT NULL,         -- PEM
    private_key_encrypted TEXT,        -- 加密后的私钥（或留空走外部 Secret Store）
    expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- audit_logs
CREATE TABLE audit_logs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    user_id TEXT,
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    ip TEXT,
    user_agent TEXT,
    metadata TEXT,                     -- JSON
    created_at TEXT NOT NULL
);
CREATE INDEX idx_audit_created ON audit_logs(created_at);
CREATE INDEX idx_audit_user ON audit_logs(user_id);
```

---

## migrations/0002_traffic_stats.sql

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
CREATE INDEX idx_stats_node ON traffic_stats(node_id, window_start);
CREATE INDEX idx_stats_route ON traffic_stats(route_id, window_start);
```

---

## 冲突校验与唯一约束的边界

- **唯一约束（DB 层）**：`users.username`、`nodes.name`、`routes.name`、`domains.hostname`。
- **应用层校验（不在 DB 建唯一索引）**：`routes` 的 `(listen_host, listen_port)` 与 `hostname` 冲突——因为存在 `0.0.0.0` vs 具体 IP、wildcard domain 等语义，需在 `server/route` 校验逻辑里处理（设计文档 §57），DB 不强制。

---

## SQLite vs PostgreSQL 差异注意

| 事项 | SQLite | PostgreSQL |
|------|--------|------------|
| 主键 `TEXT` | 可用，无原生 UUID | 可用；如需原生 `UUID` 另建 PG 迁移 |
| `BOOLEAN` | 存 0/1 | 原生 bool |
| JSON | `TEXT` 存字符串，读回 `serde_json` 解析 | `TEXT` 同理；如需查询走 `JSONB` 另建迁移 |
| 时间戳 `TEXT` | 按字典序可排序（RFC3339 UTC） | 同理；如需 `TIMESTAMPTZ` 另建迁移 |
| 并发写 | 单写者，注意 `busy_timeout` | 多连接并发 |
| 连接串 | `sqlite://tunnel.db` | `postgres://…` |

---

## 默认种子数据（tunnel-server init 时写入）

- `roles`：`admin`、`operator`、`viewer`（设计文档 §31）。
- `users`：初始 admin（`init` 时交互设置密码，Argon2id hash）。
- 生成 server identity / CA（TLS 证书）与首个 secret。
