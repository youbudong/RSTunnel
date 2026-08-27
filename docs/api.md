# REST + WebSocket 契约

> 实现见 `server/api`。Base 路径 `/api/v1`。所有响应 JSON。OpenAPI 暴露于 `/openapi.json`、`/docs`。

## 1. 认证与安全

- **Web**：登录后下发 `HttpOnly Secure SameSite` cookie；同时支持 `Authorization: Bearer <access_token>`。
- **API Token**：`Authorization: Bearer token_xxxx`（只存 hash）。
- **CSRF**：Cookie 模式需带 CSRF token（`X-CSRF-Token` 头）。
- **RBAC**：每个端点校验权限码（见 §7）；不足返回 403。

## 2. 通用约定

- 分页：`?page=1&page_size=50`；响应 `{ "items": [...], "total": 123 }`。
- 错误格式（设计文档 §22）：
```json
{ "error": { "code": "ROUTE_NOT_FOUND", "message": "Route does not exist", "request_id": "…" } }
```
- HTTP 状态码：400 校验 / 401 认证 / 403 授权 / 404 未找到 / 409 冲突 / 422 语义校验 / 429 限速 / 500 内部 / 503 不可用。

## 3. Authentication

```
POST /auth/login      { "username", "password" } → { "user": {…}, "token"? }
POST /auth/logout
POST /auth/refresh
GET  /auth/me         → { "id", "username", "email", "roles": ["admin"], "permissions": [...] }
```

## 4. Enrollment（Agent 注册）

```
POST /enroll
```
请求：`{ "bootstrap_token": "…", "node_name": "home", "platform": "linux", "architecture": "x86_64", "agent_version": "0.1.0" }`
响应：`{ "node_id": "…", "credential": "<runtime-token 只此一次>", "config_version": 0 }`
- bootstrap token 由管理员在 Web 创建 Node 时生成（一次性）。
- 成功后 bootstrap token 作废，返回运行时 credential。

## 5. Nodes

```
GET    /nodes                      → 列表（含 status、last_seen_at）
POST   /nodes                      { "name", "description"? } → 创建（可同时返回 bootstrap token）
GET    /nodes/:id                  → 详情 + 统计
PATCH  /nodes/:id                  { "name"?, "description"?, "disabled"? }
DELETE /nodes/:id                  → 需二次确认（前端）
POST   /nodes/:id/credentials      { "type": "token", "expires_at"? } → { "token": "只显示一次", "id" }
POST   /nodes/:id/credentials/:credential_id/revoke
```

Node 对象：
```json
{
  "id": "…", "name": "home", "description": null,
  "status": "online", "hostname": "nas", "platform": "linux",
  "architecture": "x86_64", "agent_version": "0.1.0",
  "remote_addr": "1.2.3.4:50000",
  "connected_at": "…", "last_seen_at": "…",
  "config_version": 184, "applied_config_version": 183, "config_status": "pending"
}
```

## 6. Routes

```
GET    /routes
POST   /routes
GET    /routes/:id
PATCH  /routes/:id
DELETE /routes/:id
POST   /routes/:id/enable
POST   /routes/:id/disable
```

Route 对象：
```json
{
  "id": "…", "name": "ssh", "node_id": "…",
  "type": "tcp", "enabled": true,
  "listen_host": "0.0.0.0", "listen_port": 2222,
  "hostname": null,
  "target_host": "192.168.1.100", "target_port": 22,
  "tls_mode": "disabled", "status": "active",
  "limits": { "max_connections": 100, "max_connection_rate": 10, "max_bandwidth": null }
}
```

创建校验（§57）：type 合法、端口范围、hostname 冲突、listen 冲突、node 存在、目标地址 SSRF 检查、ACL 合法。冲突返回 409/422。

## 7. Users / Roles / ACL

```
GET    /users
POST   /users            { "username", "email"?, "password", "roles": ["operator"] }
PATCH  /users/:id
DELETE /users/:id

GET    /roles
POST   /roles
PATCH  /roles/:id
DELETE /roles/:id

GET    /acl-rules
POST   /acl-rules        { "route_id"?, "action": "allow", "source_cidr": "10.0.0.0/8", "source_port"?, "target_host"?, "target_port"? }
DELETE /acl-rules/:id
```

## 8. Logs / Audit / Metrics

```
GET /logs?level=info&node_id=…&route_id=…
GET /audit-logs?user_id=…&action=…
GET /metrics                                    # internal 端口
GET /nodes/:id/metrics
GET /routes/:id/metrics
```

## 9. Domains / Certificates

```
GET    /domains
POST   /domains          { "hostname", "route_id"?, "tls_mode", "certificate_id"? }
DELETE /domains/:id

GET    /certificates
POST   /certificates     { "name", "hostnames": [], "mode": "acme|manual", "certificate"?, "private_key"? }
DELETE /certificates/:id
```

## 10. Health

```
GET /health     → { "status": "ok" }
GET /ready      → 200 当 DB/QUIC/HTTP 就绪，否则 503（§98）
```

## 11. WebSocket（/ws）

- 握手需携带认证（cookie 或 `?token=`，仅 TLS）。
- 服务端推送事件（§23）：
```json
{ "type": "node.status", "data": { "node_id": "…", "status": "online" } }
```
- 事件类型：`node.created/updated/online/offline`、`route.created/updated/deleted`、`config.updated`、`traffic.updated`、`log.created`。

## 12. RBAC 权限码与端点映射

| 权限码 | 端点 |
|--------|------|
| `nodes.read` | GET /nodes, /nodes/:id |
| `nodes.write` | POST/PATCH/DELETE /nodes, credentials, revoke |
| `routes.read` | GET /routes |
| `routes.write` | POST/PATCH/DELETE /routes, enable/disable |
| `users.read` | GET /users, /roles |
| `users.write` | POST/PATCH/DELETE /users, /roles |
| `logs.read` | GET /logs |
| `audit.read` | GET /audit-logs |
| `settings.read/write` | GET/PATCH /settings |

默认角色（§31）：`admin` 全权；`operator` = nodes/routes read+write；`viewer` = 全部 read。

## 13. 系统设置

```
GET    /settings
PATCH  /settings        { "limits": { "max_nodes": 10000 }, "security": { "max_login_attempts": 5 } }
```

## 14. 备份

```
GET    /backup/export    → 配置快照（YAML，不含 credential 明文）
POST   /backup/import    → 校验 → 预览 → 确认后导入
```
