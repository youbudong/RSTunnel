//! 数据库访问层。v1 默认 SQLite（docs/schema.md）；PostgreSQL 在 HA 里程碑启用。
//!
//! 迁移文件位于仓库根 `migrations/`，通过 [`sqlx::migrate!`] 内嵌到二进制。

use std::str::FromStr;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions};

/// 转发 sqlx，供调用方（测试/上层）直接使用底层驱动而无需重复声明依赖。
pub use sqlx;

pub type DbResult<T> = Result<T, sqlx::Error>;

/// 数据库句柄。内部持有 [`SqlitePool`]，可 `Clone` 以跨任务共享。
#[derive(Clone)]
pub struct Db {
    pool: SqlitePool,
}

/// 认证联表行：一条 credential + 其所属 node 的校验状态（T-08）。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct NodeCredentialRow {
    pub node_id: String,
    pub node_status: String,
    pub config_version: i64,
    pub revoked_at: Option<String>,
    pub expires_at: Option<String>,
}

/// users 表行（T-20）。`password_hash` 为 Argon2id 密文。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRow {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub password_hash: String,
    pub disabled: bool,
}

/// Route 表行（T-14）。`limits` 为 JSON 文本（NULL = 未设置），由上层反序列化。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RouteRow {
    pub id: String,
    pub name: String,
    pub node_id: String,
    pub route_type: String,
    pub enabled: bool,
    pub listen_host: Option<String>,
    pub listen_port: Option<i64>,
    pub hostname: Option<String>,
    pub target_host: String,
    pub target_port: i64,
    pub tls_mode: Option<String>,
    pub limits: Option<String>,
}

/// nodes 表行（T-21）。时间戳为 RFC3339 `TEXT`。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct NodeRow {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub status: String,
    pub hostname: Option<String>,
    pub platform: Option<String>,
    pub architecture: Option<String>,
    pub agent_version: Option<String>,
    pub remote_addr: Option<String>,
    pub last_seen_at: Option<String>,
    pub connected_at: Option<String>,
    pub config_version: i64,
    pub applied_config_version: i64,
    pub config_status: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Route 表全量行（T-21，管理面 CRUD 用）。比 [`RouteRow`] 多 `tls_mode`/`status`/时间戳。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RouteDetailRow {
    pub id: String,
    pub name: String,
    pub node_id: String,
    pub route_type: String,
    pub enabled: bool,
    pub listen_host: Option<String>,
    pub listen_port: Option<i64>,
    pub hostname: Option<String>,
    pub target_host: String,
    pub target_port: i64,
    pub tls_mode: Option<String>,
    pub status: String,
    pub limits: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// credentials 表行（T-22）。`secret_hash` 为明文 token 的 SHA-256，明文仅创建时返回一次。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CredentialRow {
    pub id: String,
    pub node_id: String,
    pub credential_type: String,
    pub secret_hash: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub last_used_at: Option<String>,
    pub created_at: String,
}

/// certificates 表行（T-27）。`hostnames` 为 JSON 数组字符串，`certificate` 为 PEM，
/// `private_key_encrypted` 存放私钥（v1 手动证书存 PEM 明文，静态加密待后续任务）。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CertificateRow {
    pub id: String,
    pub name: String,
    pub hostnames: String,
    pub certificate: String,
    pub private_key_encrypted: Option<String>,
    pub expires_at: Option<String>,
}

/// acl_rules 表行（T-34）。`route_id` 为 `NULL` 表示全局规则（作用于所有 Route）。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AclRuleRow {
    pub id: String,
    pub tenant_id: String,
    pub route_id: Option<String>,
    pub action: String,
    pub source_cidr: Option<String>,
    pub source_port: Option<i64>,
    pub target_host: Option<String>,
    pub target_port: Option<i64>,
    pub created_at: String,
}

/// audit_logs 表行（T-36）。`metadata` 为 JSON 文本（NULL = 无）。`tenant_id` 恒为 `default`，
/// v1 不参与查询，故不在此行中暴露。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditRow {
    pub id: String,
    pub user_id: Option<String>,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: Option<String>,
    pub created_at: String,
}

impl Db {
    /// 打开（必要时创建）SQLite 数据库并启用 WAL + 外键约束。
    pub async fn connect(url: &str) -> DbResult<Self> {
        let options = SqliteConnectOptions::from_str(url)?
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal);
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await?;
        Ok(Self { pool })
    }

    /// 打开单连接内存库（测试/CLI 用）。
    ///
    /// 内存 SQLite 必须单连接，否则每个池连接看到的是各自独立的空库。
    pub async fn connect_memory() -> DbResult<Self> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")?
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        Ok(Self { pool })
    }

    /// 运行内嵌迁移（幂等，可重复调用）。
    pub async fn migrate(&self) -> DbResult<()> {
        sqlx::migrate!("../../migrations").run(&self.pool).await?;
        Ok(())
    }

    /// 按 token 的 SHA-256 hash 查询 credential 及其 node 的校验状态。
    ///
    /// 仅匹配运行时凭据（`type = 'token'`）；bootstrap token 只用于 `/enroll`，不能作数据面认证。
    pub async fn find_node_credential(
        &self,
        secret_hash: &str,
    ) -> DbResult<Option<NodeCredentialRow>> {
        sqlx::query_as::<_, NodeCredentialRow>(
            "SELECT n.id AS node_id, n.status AS node_status, \
             n.config_version AS config_version, c.revoked_at AS revoked_at, c.expires_at AS expires_at \
             FROM credentials c JOIN nodes n ON n.id = c.node_id \
             WHERE c.secret_hash = ? AND c.type = 'token'",
        )
        .bind(secret_hash)
        .fetch_optional(&self.pool)
        .await
    }

    /// 标记 node 上线：写入 `remote_addr`/`agent_version` 与上线时间戳，`status = 'online'`。
    pub async fn set_node_online(
        &self,
        node_id: &str,
        remote_addr: &str,
        agent_version: &str,
        ts: &str,
    ) -> DbResult<()> {
        sqlx::query(
            "UPDATE nodes SET status = 'online', remote_addr = ?, agent_version = ?, \
             connected_at = ?, last_seen_at = ?, updated_at = ? WHERE id = ?",
        )
        .bind(remote_addr)
        .bind(agent_version)
        .bind(ts)
        .bind(ts)
        .bind(ts)
        .bind(node_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 标记 node 下线：仅当当前为 `online` 时置 `offline`（避免覆盖 `disabled` 等状态）。
    pub async fn set_node_offline(&self, node_id: &str, ts: &str) -> DbResult<()> {
        sqlx::query(
            "UPDATE nodes SET status = 'offline', last_seen_at = ?, updated_at = ? \
             WHERE id = ? AND status = 'online'",
        )
        .bind(ts)
        .bind(ts)
        .bind(node_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// 按 username 查询用户（登录用）。
    pub async fn find_user_by_username(&self, username: &str) -> DbResult<Option<UserRow>> {
        sqlx::query_as::<_, UserRow>(
            "SELECT id, username, email, password_hash, disabled FROM users WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
    }

    /// 查询某用户的全部角色名（按 name 排序）。无角色时返回空列表。
    pub async fn list_role_names_for_user(&self, user_id: &str) -> DbResult<Vec<String>> {
        sqlx::query_scalar(
            "SELECT r.name FROM roles r \
             JOIN user_roles ur ON ur.role_id = r.id \
             WHERE ur.user_id = ? ORDER BY r.name",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
    }

    /// 用户总数（T-20 首次引导用：0 = 未初始化，允许创建初始 admin）。
    pub async fn count_users(&self) -> DbResult<i64> {
        sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await
    }

    /// 创建用户（T-20）。`password_hash` 为 Argon2id 密文（见 [`tunnel_auth::hash_password`]）。
    pub async fn create_user(
        &self,
        id: &str,
        username: &str,
        email: Option<&str>,
        password_hash: &str,
        disabled: bool,
        ts: &str,
    ) -> DbResult<()> {
        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash, disabled, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(username)
        .bind(email)
        .bind(password_hash)
        .bind(disabled)
        .bind(ts)
        .bind(ts)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 按名字查角色 id（首次引导给新用户指派 `admin` 角色）。不存在返回 `None`。
    pub async fn find_role_id_by_name(&self, name: &str) -> DbResult<Option<String>> {
        sqlx::query_scalar("SELECT id FROM roles WHERE name = ?")
            .bind(name)
            .fetch_optional(&self.pool)
            .await
    }

    /// 给用户指派角色（插入 user_roles 关联）。
    pub async fn assign_user_role(&self, user_id: &str, role_id: &str) -> DbResult<()> {
        sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)")
            .bind(user_id)
            .bind(role_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// 列出全部 Route（含禁用），按 name 排序。供 Route Manager 构建/热更新使用。
    pub async fn list_routes(&self) -> DbResult<Vec<RouteRow>> {
        sqlx::query_as::<_, RouteRow>(
            "SELECT id, name, node_id, type AS route_type, enabled, listen_host, listen_port, \
             hostname, target_host, target_port, tls_mode, limits \
             FROM routes ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await
    }

    /// 列出某个 Node 的全部 Route（含禁用），按 name 排序。供配置快照/下发使用。
    pub async fn list_routes_for_node(&self, node_id: &str) -> DbResult<Vec<RouteRow>> {
        sqlx::query_as::<_, RouteRow>(
            "SELECT id, name, node_id, type AS route_type, enabled, listen_host, listen_port, \
             hostname, target_host, target_port, tls_mode, limits \
             FROM routes WHERE node_id = ? ORDER BY name",
        )
        .bind(node_id)
        .fetch_all(&self.pool)
        .await
    }

    /// 读取 Node 当前配置版本（不存在返回 `Err(RowNotFound)`）。
    pub async fn get_config_version(&self, node_id: &str) -> DbResult<i64> {
        sqlx::query_scalar("SELECT config_version FROM nodes WHERE id = ?")
            .bind(node_id)
            .fetch_one(&self.pool)
            .await
    }

    /// Node 配置版本自增：`config_version += 1`、`config_status = 'pending'`，返回新版本。
    ///
    /// 任何影响该 Node 的 Route/ACL/Domain 变更后调用（设计文档 §10/§28）。离线 Node 不会
    /// 立即 ACK，`config_status` 保持 `pending`，待其上线走快照收敛。
    pub async fn bump_config_version(&self, node_id: &str, ts: &str) -> DbResult<i64> {
        sqlx::query_scalar(
            "UPDATE nodes SET config_version = config_version + 1, \
             config_status = 'pending', updated_at = ? \
             WHERE id = ? RETURNING config_version",
        )
        .bind(ts)
        .bind(node_id)
        .fetch_one(&self.pool)
        .await
    }

    /// 记录 Agent 已应用某配置版本：`applied_config_version = version`、`config_status = 'synced'`。
    pub async fn set_node_applied_config(
        &self,
        node_id: &str,
        version: i64,
        ts: &str,
    ) -> DbResult<()> {
        sqlx::query(
            "UPDATE nodes SET applied_config_version = ?, config_status = 'synced', updated_at = ? \
             WHERE id = ?",
        )
        .bind(version)
        .bind(ts)
        .bind(node_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 标记 Node 配置应用失败（Agent 回 `applied = false`）：`config_status = 'failed'`（设计文档 §28）。
    pub async fn set_node_config_failed(&self, node_id: &str, ts: &str) -> DbResult<()> {
        sqlx::query("UPDATE nodes SET config_status = 'failed', updated_at = ? WHERE id = ?")
            .bind(ts)
            .bind(node_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// 列出全部 Node，按 name 排序。
    pub async fn list_nodes(&self) -> DbResult<Vec<NodeRow>> {
        sqlx::query_as::<_, NodeRow>(
            "SELECT id, name, description, status, hostname, platform, architecture, \
             agent_version, remote_addr, last_seen_at, connected_at, config_version, \
             applied_config_version, config_status, created_at, updated_at \
             FROM nodes ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await
    }

    /// 已注册 Node 总数（T-38：供 `tunnel_nodes_total` 指标）。
    pub async fn count_nodes(&self) -> DbResult<i64> {
        sqlx::query_scalar("SELECT COUNT(*) FROM nodes")
            .fetch_one(&self.pool)
            .await
    }

    /// 按 id 查询 Node；不存在返回 `None`。
    pub async fn get_node(&self, id: &str) -> DbResult<Option<NodeRow>> {
        sqlx::query_as::<_, NodeRow>(
            "SELECT id, name, description, status, hostname, platform, architecture, \
             agent_version, remote_addr, last_seen_at, connected_at, config_version, \
             applied_config_version, config_status, created_at, updated_at \
             FROM nodes WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
    }

    /// Node 是否存在（按 id）。
    pub async fn node_exists(&self, id: &str) -> DbResult<bool> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes WHERE id = ?")
            .bind(id)
            .fetch_one(&self.pool)
            .await?;
        Ok(count > 0)
    }

    /// Node 名称是否已被占用（可排除自身，供 PATCH 改名时用）。
    pub async fn node_name_exists(&self, name: &str, exclude_id: Option<&str>) -> DbResult<bool> {
        let count: i64 = match exclude_id {
            Some(id) => {
                sqlx::query_scalar("SELECT COUNT(*) FROM nodes WHERE name = ? AND id != ?")
                    .bind(name)
                    .bind(id)
                    .fetch_one(&self.pool)
                    .await?
            }
            None => {
                sqlx::query_scalar("SELECT COUNT(*) FROM nodes WHERE name = ?")
                    .bind(name)
                    .fetch_one(&self.pool)
                    .await?
            }
        };
        Ok(count > 0)
    }

    /// 创建 Node（初始 `status = 'pending'`、`config_version = 0`）。
    pub async fn create_node(
        &self,
        id: &str,
        name: &str,
        description: Option<&str>,
        ts: &str,
    ) -> DbResult<()> {
        sqlx::query(
            "INSERT INTO nodes (id, name, description, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(name)
        .bind(description)
        .bind(ts)
        .bind(ts)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 更新 Node 的 name/description（`name` 唯一冲突由调用方预检 + 唯一约束兜底）。
    pub async fn update_node(
        &self,
        id: &str,
        name: &str,
        description: Option<&str>,
        ts: &str,
    ) -> DbResult<()> {
        sqlx::query("UPDATE nodes SET name = ?, description = ?, updated_at = ? WHERE id = ?")
            .bind(name)
            .bind(description)
            .bind(ts)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// 删除 Node（其 Route 由外键 `ON DELETE CASCADE` 级联删除）。
    pub async fn delete_node(&self, id: &str) -> DbResult<()> {
        sqlx::query("DELETE FROM nodes WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// 按 id 查询 Route 全量行；不存在返回 `None`。
    pub async fn get_route(&self, id: &str) -> DbResult<Option<RouteDetailRow>> {
        sqlx::query_as::<_, RouteDetailRow>(
            "SELECT id, name, node_id, type AS route_type, enabled, listen_host, listen_port, \
             hostname, target_host, target_port, tls_mode, status, limits, created_at, updated_at \
             FROM routes WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
    }

    /// 列出全部 Route 全量行（管理面），按 name 排序。
    pub async fn list_routes_detail(&self) -> DbResult<Vec<RouteDetailRow>> {
        sqlx::query_as::<_, RouteDetailRow>(
            "SELECT id, name, node_id, type AS route_type, enabled, listen_host, listen_port, \
             hostname, target_host, target_port, tls_mode, status, limits, created_at, updated_at \
             FROM routes ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await
    }

    /// Route 名称是否已被占用（可排除自身）。
    pub async fn route_name_exists(&self, name: &str, exclude_id: Option<&str>) -> DbResult<bool> {
        let count: i64 = match exclude_id {
            Some(id) => {
                sqlx::query_scalar("SELECT COUNT(*) FROM routes WHERE name = ? AND id != ?")
                    .bind(name)
                    .bind(id)
                    .fetch_one(&self.pool)
                    .await?
            }
            None => {
                sqlx::query_scalar("SELECT COUNT(*) FROM routes WHERE name = ?")
                    .bind(name)
                    .fetch_one(&self.pool)
                    .await?
            }
        };
        Ok(count > 0)
    }

    /// 是否存在其他 Route 占用同一 hostname（HTTP/HTTPS 路由唯一，§57）。
    pub async fn route_hostname_exists(
        &self,
        hostname: &str,
        exclude_id: Option<&str>,
    ) -> DbResult<bool> {
        let count: i64 = match exclude_id {
            Some(id) => {
                sqlx::query_scalar("SELECT COUNT(*) FROM routes WHERE hostname = ? AND id != ?")
                    .bind(hostname)
                    .bind(id)
                    .fetch_one(&self.pool)
                    .await?
            }
            None => {
                sqlx::query_scalar("SELECT COUNT(*) FROM routes WHERE hostname = ?")
                    .bind(hostname)
                    .fetch_one(&self.pool)
                    .await?
            }
        };
        Ok(count > 0)
    }

    /// 是否存在其他 Route 占用同一监听地址（TCP/UDP 唯一，§57）。
    pub async fn route_listen_exists(
        &self,
        listen_host: &str,
        listen_port: i64,
        exclude_id: Option<&str>,
    ) -> DbResult<bool> {
        let count: i64 = match exclude_id {
            Some(id) => sqlx::query_scalar(
                "SELECT COUNT(*) FROM routes WHERE listen_host = ? AND listen_port = ? AND id != ?",
            )
            .bind(listen_host)
            .bind(listen_port)
            .bind(id)
            .fetch_one(&self.pool)
            .await?,
            None => {
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM routes WHERE listen_host = ? AND listen_port = ?",
                )
                .bind(listen_host)
                .bind(listen_port)
                .fetch_one(&self.pool)
                .await?
            }
        };
        Ok(count > 0)
    }

    /// 创建 Route。`limits` 为 JSON 文本（可为 `None`）。
    #[allow(clippy::too_many_arguments)]
    pub async fn create_route(
        &self,
        id: &str,
        name: &str,
        node_id: &str,
        route_type: &str,
        enabled: bool,
        listen_host: Option<&str>,
        listen_port: Option<i64>,
        hostname: Option<&str>,
        target_host: &str,
        target_port: i64,
        tls_mode: &str,
        limits: Option<&str>,
        ts: &str,
    ) -> DbResult<()> {
        sqlx::query(
            "INSERT INTO routes \
             (id, name, node_id, type, enabled, listen_host, listen_port, hostname, \
              target_host, target_port, tls_mode, status, limits, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?, ?)",
        )
        .bind(id)
        .bind(name)
        .bind(node_id)
        .bind(route_type)
        .bind(enabled)
        .bind(listen_host)
        .bind(listen_port)
        .bind(hostname)
        .bind(target_host)
        .bind(target_port)
        .bind(tls_mode)
        .bind(limits)
        .bind(ts)
        .bind(ts)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 更新 Route 全量字段（PATCH 合并后调用）。
    #[allow(clippy::too_many_arguments)]
    pub async fn update_route(
        &self,
        id: &str,
        name: &str,
        node_id: &str,
        route_type: &str,
        enabled: bool,
        listen_host: Option<&str>,
        listen_port: Option<i64>,
        hostname: Option<&str>,
        target_host: &str,
        target_port: i64,
        tls_mode: &str,
        limits: Option<&str>,
        ts: &str,
    ) -> DbResult<()> {
        sqlx::query(
            "UPDATE routes SET name = ?, node_id = ?, type = ?, enabled = ?, listen_host = ?, \
             listen_port = ?, hostname = ?, target_host = ?, target_port = ?, tls_mode = ?, \
             limits = ?, updated_at = ? WHERE id = ?",
        )
        .bind(name)
        .bind(node_id)
        .bind(route_type)
        .bind(enabled)
        .bind(listen_host)
        .bind(listen_port)
        .bind(hostname)
        .bind(target_host)
        .bind(target_port)
        .bind(tls_mode)
        .bind(limits)
        .bind(ts)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 启用/禁用 Route。
    pub async fn set_route_enabled(&self, id: &str, enabled: bool, ts: &str) -> DbResult<()> {
        sqlx::query("UPDATE routes SET enabled = ?, updated_at = ? WHERE id = ?")
            .bind(enabled)
            .bind(ts)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// 删除 Route。
    pub async fn delete_route(&self, id: &str) -> DbResult<()> {
        sqlx::query("DELETE FROM routes WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// 写入一条审计日志（设计文档 §40）。
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_audit_log(
        &self,
        id: &str,
        user_id: Option<&str>,
        action: &str,
        resource_type: &str,
        resource_id: &str,
        ip: Option<&str>,
        user_agent: Option<&str>,
        metadata: Option<&str>,
        ts: &str,
    ) -> DbResult<()> {
        sqlx::query(
            "INSERT INTO audit_logs \
             (id, user_id, action, resource_type, resource_id, ip, user_agent, metadata, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(user_id)
        .bind(action)
        .bind(resource_type)
        .bind(resource_id)
        .bind(ip)
        .bind(user_agent)
        .bind(metadata)
        .bind(ts)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 分页查询审计日志（T-36，§40/api.md §8）。按时间倒序；`user_id`/`action` 可选过滤。
    ///
    /// 空字符串过滤值按「不过滤」处理由上层保证（query 参数缺省为 `None`）。
    pub async fn list_audit_logs(
        &self,
        user_id: Option<&str>,
        action: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> DbResult<Vec<AuditRow>> {
        sqlx::query_as::<_, AuditRow>(
            "SELECT id, user_id, action, resource_type, resource_id, ip, user_agent, metadata, \
             created_at \
             FROM audit_logs \
             WHERE (? IS NULL OR user_id = ?) AND (? IS NULL OR action = ?) \
             ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
        )
        .bind(user_id)
        .bind(user_id)
        .bind(action)
        .bind(action)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
    }

    /// 创建凭据（bootstrap/token）。`secret_hash` 为明文 token 的 SHA-256，明文不落库。
    pub async fn create_credential(
        &self,
        id: &str,
        node_id: &str,
        credential_type: &str,
        secret_hash: &str,
        expires_at: Option<&str>,
        ts: &str,
    ) -> DbResult<()> {
        sqlx::query(
            "INSERT INTO credentials (id, node_id, type, secret_hash, expires_at, created_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(node_id)
        .bind(credential_type)
        .bind(secret_hash)
        .bind(expires_at)
        .bind(ts)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 按 hash + 类型查询凭据（bootstrap 用 `'bootstrap'`，运行时用 `'token'`）。
    pub async fn find_credential_by_hash(
        &self,
        secret_hash: &str,
        credential_type: &str,
    ) -> DbResult<Option<CredentialRow>> {
        sqlx::query_as::<_, CredentialRow>(
            "SELECT id, node_id, type AS credential_type, secret_hash, expires_at, revoked_at, \
             last_used_at, created_at \
             FROM credentials WHERE secret_hash = ? AND type = ?",
        )
        .bind(secret_hash)
        .bind(credential_type)
        .fetch_optional(&self.pool)
        .await
    }

    /// 按 id 查询凭据。
    pub async fn get_credential(&self, id: &str) -> DbResult<Option<CredentialRow>> {
        sqlx::query_as::<_, CredentialRow>(
            "SELECT id, node_id, type AS credential_type, secret_hash, expires_at, revoked_at, \
             last_used_at, created_at \
             FROM credentials WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
    }

    /// 吊销凭据（写 `revoked_at`，不删除行）。
    pub async fn revoke_credential(&self, id: &str, ts: &str) -> DbResult<()> {
        sqlx::query("UPDATE credentials SET revoked_at = ? WHERE id = ?")
            .bind(ts)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// 更新 node 的 agent 元数据（`/enroll` 上报，§4）。
    pub async fn set_node_agent_meta(
        &self,
        node_id: &str,
        hostname: Option<&str>,
        platform: Option<&str>,
        architecture: Option<&str>,
        agent_version: Option<&str>,
        ts: &str,
    ) -> DbResult<()> {
        sqlx::query(
            "UPDATE nodes SET hostname = ?, platform = ?, architecture = ?, agent_version = ?, \
             updated_at = ? WHERE id = ?",
        )
        .bind(hostname)
        .bind(platform)
        .bind(architecture)
        .bind(agent_version)
        .bind(ts)
        .bind(node_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 全量证书列表（T-27：TLS 终止按 SNI 选证书，hostnames 为 JSON 数组字符串）。
    pub async fn list_certificates(&self) -> DbResult<Vec<CertificateRow>> {
        sqlx::query_as::<_, CertificateRow>(
            "SELECT id, name, hostnames, certificate, private_key_encrypted, expires_at \
             FROM certificates ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await
    }

    /// 写入一张手动证书（v1：`private_key` 明文 PEM 存入 `private_key_encrypted`）。
    #[allow(clippy::too_many_arguments)]
    pub async fn create_certificate(
        &self,
        id: &str,
        name: &str,
        hostnames_json: &str,
        certificate_pem: &str,
        private_key_pem: &str,
        expires_at: Option<&str>,
        ts: &str,
    ) -> DbResult<()> {
        sqlx::query(
            "INSERT INTO certificates \
             (id, name, hostnames, certificate, private_key_encrypted, expires_at, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(name)
        .bind(hostnames_json)
        .bind(certificate_pem)
        .bind(private_key_pem)
        .bind(expires_at)
        .bind(ts)
        .bind(ts)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 删除一张证书。
    pub async fn delete_certificate(&self, id: &str) -> DbResult<()> {
        sqlx::query("DELETE FROM certificates WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// 列出全部 ACL 规则（含全局规则，`route_id = NULL`）。
    pub async fn list_acl_rules(&self) -> DbResult<Vec<AclRuleRow>> {
        sqlx::query_as::<_, AclRuleRow>(
            "SELECT id, tenant_id, route_id, action, source_cidr, source_port, \
             target_host, target_port, created_at FROM acl_rules ORDER BY created_at",
        )
        .fetch_all(&self.pool)
        .await
    }

    /// 列出某 Route 专属的 ACL 规则（不含全局规则）。
    pub async fn list_acl_rules_for_route(&self, route_id: &str) -> DbResult<Vec<AclRuleRow>> {
        sqlx::query_as::<_, AclRuleRow>(
            "SELECT id, tenant_id, route_id, action, source_cidr, source_port, \
             target_host, target_port, created_at FROM acl_rules WHERE route_id = ? \
             ORDER BY created_at",
        )
        .bind(route_id)
        .fetch_all(&self.pool)
        .await
    }

    /// 按 id 取单条 ACL 规则。
    pub async fn get_acl_rule(&self, id: &str) -> DbResult<Option<AclRuleRow>> {
        sqlx::query_as::<_, AclRuleRow>(
            "SELECT id, tenant_id, route_id, action, source_cidr, source_port, \
             target_host, target_port, created_at FROM acl_rules WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
    }

    /// 写入一条 ACL 规则。`route_id = None` 表示全局规则。
    #[allow(clippy::too_many_arguments)]
    pub async fn create_acl_rule(
        &self,
        id: &str,
        route_id: Option<&str>,
        action: &str,
        source_cidr: Option<&str>,
        source_port: Option<i64>,
        target_host: Option<&str>,
        target_port: Option<i64>,
        ts: &str,
    ) -> DbResult<()> {
        sqlx::query(
            "INSERT INTO acl_rules \
             (id, tenant_id, route_id, action, source_cidr, source_port, \
              target_host, target_port, created_at) \
             VALUES (?, 'default', ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(route_id)
        .bind(action)
        .bind(source_cidr)
        .bind(source_port)
        .bind(target_host)
        .bind(target_port)
        .bind(ts)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 删除一条 ACL 规则。
    pub async fn delete_acl_rule(&self, id: &str) -> DbResult<()> {
        sqlx::query("DELETE FROM acl_rules WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const NODE_ID: &str = "11111111-1111-4111-8111-111111111111";
    const NOW: &str = "2026-08-27T00:00:00Z";

    async fn seeded_db() -> Db {
        let db = Db::connect_memory().await.unwrap();
        db.migrate().await.unwrap();
        sqlx::query(
            "INSERT INTO nodes (id, name, config_version, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(NODE_ID)
        .bind("node-a")
        .bind(7i64)
        .bind(NOW)
        .bind(NOW)
        .execute(db.pool())
        .await
        .unwrap();
        db
    }

    async fn insert_route(db: &Db, id: &str, node_id: &str, name: &str, target_port: i64) {
        sqlx::query(
            "INSERT INTO routes \
             (id, name, node_id, type, enabled, listen_host, listen_port, target_host, target_port, \
              status, created_at, updated_at) \
             VALUES (?, ?, ?, 'tcp', 1, '127.0.0.1', 8080, '192.168.1.100', ?, 'active', ?, ?)",
        )
        .bind(id)
        .bind(name)
        .bind(node_id)
        .bind(target_port)
        .bind(NOW)
        .bind(NOW)
        .execute(db.pool())
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn bump_config_version_increments_and_marks_pending() {
        let db = seeded_db().await;
        let v = db.bump_config_version(NODE_ID, NOW).await.unwrap();
        assert_eq!(v, 8);
        assert_eq!(db.get_config_version(NODE_ID).await.unwrap(), 8);
        let status: String = sqlx::query_scalar("SELECT config_status FROM nodes WHERE id = ?")
            .bind(NODE_ID)
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(status, "pending");
    }

    #[tokio::test]
    async fn applied_config_marks_synced() {
        let db = seeded_db().await;
        db.set_node_applied_config(NODE_ID, 8, NOW).await.unwrap();
        let (applied, status): (i64, String) =
            sqlx::query_as("SELECT applied_config_version, config_status FROM nodes WHERE id = ?")
                .bind(NODE_ID)
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(applied, 8);
        assert_eq!(status, "synced");
    }

    #[tokio::test]
    async fn config_failed_marks_failed() {
        let db = seeded_db().await;
        db.set_node_config_failed(NODE_ID, NOW).await.unwrap();
        let status: String = sqlx::query_scalar("SELECT config_status FROM nodes WHERE id = ?")
            .bind(NODE_ID)
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(status, "failed");
    }

    #[tokio::test]
    async fn list_routes_for_node_filters_by_node() {
        let db = seeded_db().await;
        let other = "99999999-9999-4999-8999-999999999999";
        sqlx::query(
            "INSERT INTO nodes (id, name, config_version, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(other)
        .bind("node-b")
        .bind(0i64)
        .bind(NOW)
        .bind(NOW)
        .execute(db.pool())
        .await
        .unwrap();
        insert_route(
            &db,
            "33333333-3333-4333-8333-333333333333",
            NODE_ID,
            "a",
            22,
        )
        .await;
        insert_route(&db, "44444444-4444-4444-8444-444444444444", other, "b", 80).await;

        let mine = db.list_routes_for_node(NODE_ID).await.unwrap();
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].name, "a");
    }

    #[tokio::test]
    async fn acl_rule_crud_and_route_scoping() {
        let db = seeded_db().await;
        let route = "33333333-3333-4333-8333-333333333333";
        insert_route(&db, route, NODE_ID, "ssh", 22).await;

        // 全局规则（route_id = None）+ 本 route 规则各一条。
        db.create_acl_rule(
            "acl-global",
            None,
            "deny",
            Some("0.0.0.0/0"),
            None,
            None,
            None,
            NOW,
        )
        .await
        .unwrap();
        db.create_acl_rule(
            "acl-route",
            Some(route),
            "allow",
            Some("10.0.0.0/8"),
            None,
            None,
            None,
            NOW,
        )
        .await
        .unwrap();

        // 全量含全局 + 本 route。
        let all = db.list_acl_rules().await.unwrap();
        assert_eq!(all.len(), 2);
        // route 作用域仅本 route。
        let scoped = db.list_acl_rules_for_route(route).await.unwrap();
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].id, "acl-route");
        assert_eq!(scoped[0].route_id.as_deref(), Some(route));

        // 取单条。
        let got = db.get_acl_rule("acl-global").await.unwrap().unwrap();
        assert_eq!(got.action, "deny");
        assert_eq!(got.source_cidr.as_deref(), Some("0.0.0.0/0"));
        assert!(got.route_id.is_none());

        // 删除。
        db.delete_acl_rule("acl-route").await.unwrap();
        assert!(db.get_acl_rule("acl-route").await.unwrap().is_none());
        assert_eq!(db.list_acl_rules().await.unwrap().len(), 1);
    }
}
