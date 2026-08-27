//! 配置快照的导出 / 导入（T-42，docs §99/§100）。
//!
//! 两种用途：
//! * `export` / `import` —— 控制面配置（nodes/routes/domains/acl），**不含**凭据与证书私钥；
//! * `backup` / `restore` —— 灾难恢复全量快照，额外含凭据哈希与证书。
//!
//! 导入前必须 `validate` → `preview` → `confirm`（§99「不能直接覆盖生产配置」）：
//! 默认 `apply = false` 仅预览、不改库；`--yes` 才落库，且按主键「插入不存在、跳过已存在」，
//! 永不覆盖现有行。

use std::collections::HashSet;

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use tunnel_db::Db;

// ---------------------------------------------------------------------------
// 行类型（对应 migrations/0001_initial.sql；tenant_id 恒为 'default'，不入快照）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Node {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connected_at: Option<String>,
    pub config_version: i64,
    pub applied_config_version: i64,
    pub config_status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Route {
    pub id: String,
    pub name: String,
    pub node_id: String,
    #[serde(rename = "type")]
    pub route_type: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub target_host: String,
    pub target_port: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_mode: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Domain {
    pub id: String,
    pub hostname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_id: Option<String>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AclRule {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_id: Option<String>,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_cidr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_port: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_port: Option<i64>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Credential {
    pub id: String,
    pub node_id: String,
    #[serde(rename = "type")]
    pub credential_type: String,
    pub secret_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Certificate {
    pub id: String,
    pub name: String,
    pub hostnames: String,
    pub certificate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_encrypted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

// ---------------------------------------------------------------------------
// 快照
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub nodes: Vec<Node>,
    pub routes: Vec<Route>,
    pub domains: Vec<Domain>,
    pub acl_rules: Vec<AclRule>,
    /// 仅 `backup`/`restore` 使用（§100：凭据不允许普通导出）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<Credential>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<Certificate>,
}

impl Snapshot {
    /// 从数据库读取快照。`include_secrets` 控制是否包含凭据与证书。
    pub async fn from_db(db: &Db, include_secrets: bool) -> anyhow::Result<Self> {
        let nodes = sqlx::query_as::<_, Node>(
            "SELECT id, name, description, status, hostname, platform, architecture, \
             agent_version, remote_addr, last_seen_at, connected_at, config_version, \
             applied_config_version, config_status, created_at, updated_at \
             FROM nodes ORDER BY name",
        )
        .fetch_all(db.pool())
        .await?;
        let routes = sqlx::query_as::<_, Route>(
            "SELECT id, name, node_id, type AS route_type, enabled, listen_host, listen_port, \
             hostname, target_host, target_port, tls_mode, status, limits, created_at, updated_at \
             FROM routes ORDER BY name",
        )
        .fetch_all(db.pool())
        .await?;
        let domains = sqlx::query_as::<_, Domain>(
            "SELECT id, hostname, route_id, tls_mode, certificate_id, enabled, created_at, updated_at \
             FROM domains ORDER BY hostname",
        )
        .fetch_all(db.pool())
        .await?;
        let acl_rules = sqlx::query_as::<_, AclRule>(
            "SELECT id, route_id, action, source_cidr, source_port, target_host, target_port, created_at \
             FROM acl_rules ORDER BY created_at",
        )
        .fetch_all(db.pool())
        .await?;

        let (credentials, certificates) = if include_secrets {
            let credentials = sqlx::query_as::<_, Credential>(
                "SELECT id, node_id, type AS credential_type, secret_hash, expires_at, revoked_at, \
                 last_used_at, created_at FROM credentials ORDER BY created_at",
            )
            .fetch_all(db.pool())
            .await?;
            let certificates = sqlx::query_as::<_, Certificate>(
                "SELECT id, name, hostnames, certificate, private_key_encrypted, expires_at, \
                 created_at, updated_at FROM certificates ORDER BY name",
            )
            .fetch_all(db.pool())
            .await?;
            (credentials, certificates)
        } else {
            (Vec::new(), Vec::new())
        };

        Ok(Self {
            nodes,
            routes,
            domains,
            acl_rules,
            credentials,
            certificates,
        })
    }

    pub fn to_yaml(&self) -> anyhow::Result<String> {
        serde_yaml::to_string(self).context("serialize snapshot to YAML")
    }

    pub fn from_yaml(s: &str) -> anyhow::Result<Self> {
        serde_yaml::from_str(s).context("parse snapshot YAML")
    }

    /// 快照内引用完整性校验（导入前必须通过）。
    pub fn validate(&self) -> anyhow::Result<()> {
        let node_ids: HashSet<&str> = self.nodes.iter().map(|n| n.id.as_str()).collect();
        let route_ids: HashSet<&str> = self.routes.iter().map(|r| r.id.as_str()).collect();

        for n in &self.nodes {
            if n.id.trim().is_empty() || n.name.trim().is_empty() {
                bail!("node 存在空 id/name");
            }
        }
        for r in &self.routes {
            if r.id.trim().is_empty() || r.name.trim().is_empty() || r.target_host.trim().is_empty()
            {
                bail!("route {} 存在空必填字段", r.id);
            }
            if !node_ids.contains(r.node_id.as_str()) {
                bail!("route {} 引用了不存在的 node {}", r.id, r.node_id);
            }
        }
        for a in &self.acl_rules {
            if a.id.trim().is_empty() || a.action.trim().is_empty() {
                bail!("acl_rule 存在空 id/action");
            }
            if let Some(rid) = &a.route_id {
                if !route_ids.contains(rid.as_str()) {
                    bail!("acl_rule {} 引用了不存在的 route {}", a.id, rid);
                }
            }
        }
        for d in &self.domains {
            if d.id.trim().is_empty() || d.hostname.trim().is_empty() {
                bail!("domain {} 存在空 id/hostname", d.id);
            }
            if let Some(rid) = &d.route_id {
                if !route_ids.contains(rid.as_str()) {
                    bail!("domain {} 引用了不存在的 route {}", d.id, rid);
                }
            }
            if let Some(cid) = &d.certificate_id {
                if !self.certificates.iter().any(|c| c.id == *cid) {
                    bail!("domain {} 引用了不存在的 certificate {}", d.id, cid);
                }
            }
        }
        for c in &self.credentials {
            if c.id.trim().is_empty()
                || c.node_id.trim().is_empty()
                || c.secret_hash.trim().is_empty()
            {
                bail!("credential 存在空必填字段");
            }
            if !node_ids.contains(c.node_id.as_str()) {
                bail!("credential {} 引用了不存在的 node {}", c.id, c.node_id);
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 恢复报告
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TableCounts {
    pub inserted: usize,
    pub skipped: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoreReport {
    pub nodes: TableCounts,
    pub routes: TableCounts,
    pub domains: TableCounts,
    pub acl_rules: TableCounts,
    pub credentials: TableCounts,
    pub certificates: TableCounts,
}

impl RestoreReport {
    /// 单行预览：`nodes: 插入 1，跳过 0`。
    pub fn render(&self) -> String {
        let mut lines = Vec::new();
        for (name, counts) in [
            ("nodes", &self.nodes),
            ("routes", &self.routes),
            ("domains", &self.domains),
            ("acl_rules", &self.acl_rules),
            ("credentials", &self.credentials),
            ("certificates", &self.certificates),
        ] {
            if counts.inserted == 0 && counts.skipped == 0 {
                continue;
            }
            lines.push(format!(
                "{name}: 插入 {}，跳过 {}",
                counts.inserted, counts.skipped
            ));
        }
        if lines.is_empty() {
            "（无变更）".to_string()
        } else {
            lines.join("\n")
        }
    }
}

// ---------------------------------------------------------------------------
// 恢复
// ---------------------------------------------------------------------------

/// 把快照写回数据库。`apply = false` 仅预览（validate 后返回报告、不改库）。
/// 按主键「不存在则插入、已存在则跳过」，永不覆盖现有行（§99）。
pub async fn restore(db: &Db, snapshot: &Snapshot, apply: bool) -> anyhow::Result<RestoreReport> {
    snapshot.validate()?;
    let mut report = RestoreReport::default();

    // 顺序满足外键：nodes → certificates → routes → acl_rules → domains → credentials。
    for n in &snapshot.nodes {
        if id_exists(db, "nodes", &n.id).await? {
            report.nodes.skipped += 1;
            continue;
        }
        if apply {
            insert_node(db, n).await?;
        }
        report.nodes.inserted += 1;
    }
    for c in &snapshot.certificates {
        if id_exists(db, "certificates", &c.id).await? {
            report.certificates.skipped += 1;
            continue;
        }
        if apply {
            insert_certificate(db, c).await?;
        }
        report.certificates.inserted += 1;
    }
    for r in &snapshot.routes {
        if id_exists(db, "routes", &r.id).await? {
            report.routes.skipped += 1;
            continue;
        }
        if apply {
            insert_route(db, r).await?;
        }
        report.routes.inserted += 1;
    }
    for a in &snapshot.acl_rules {
        if id_exists(db, "acl_rules", &a.id).await? {
            report.acl_rules.skipped += 1;
            continue;
        }
        if apply {
            insert_acl_rule(db, a).await?;
        }
        report.acl_rules.inserted += 1;
    }
    for d in &snapshot.domains {
        if id_exists(db, "domains", &d.id).await? {
            report.domains.skipped += 1;
            continue;
        }
        if apply {
            insert_domain(db, d).await?;
        }
        report.domains.inserted += 1;
    }
    for c in &snapshot.credentials {
        if id_exists(db, "credentials", &c.id).await? {
            report.credentials.skipped += 1;
            continue;
        }
        if apply {
            insert_credential(db, c).await?;
        }
        report.credentials.inserted += 1;
    }

    Ok(report)
}

async fn id_exists(db: &Db, table: &'static str, id: &str) -> anyhow::Result<bool> {
    let sql = match table {
        "nodes" => "SELECT COUNT(*) FROM nodes WHERE id = ?",
        "routes" => "SELECT COUNT(*) FROM routes WHERE id = ?",
        "domains" => "SELECT COUNT(*) FROM domains WHERE id = ?",
        "acl_rules" => "SELECT COUNT(*) FROM acl_rules WHERE id = ?",
        "credentials" => "SELECT COUNT(*) FROM credentials WHERE id = ?",
        "certificates" => "SELECT COUNT(*) FROM certificates WHERE id = ?",
        _ => bail!("unknown table {table}"),
    };
    let n: i64 = sqlx::query_scalar(sql)
        .bind(id)
        .fetch_one(db.pool())
        .await?;
    Ok(n > 0)
}

async fn insert_node(db: &Db, n: &Node) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO nodes \
         (id, tenant_id, name, description, status, hostname, platform, architecture, \
          agent_version, remote_addr, last_seen_at, connected_at, config_version, \
          applied_config_version, config_status, created_at, updated_at) \
         VALUES (?, 'default', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&n.id)
    .bind(&n.name)
    .bind(n.description.as_deref())
    .bind(&n.status)
    .bind(n.hostname.as_deref())
    .bind(n.platform.as_deref())
    .bind(n.architecture.as_deref())
    .bind(n.agent_version.as_deref())
    .bind(n.remote_addr.as_deref())
    .bind(n.last_seen_at.as_deref())
    .bind(n.connected_at.as_deref())
    .bind(n.config_version)
    .bind(n.applied_config_version)
    .bind(&n.config_status)
    .bind(&n.created_at)
    .bind(&n.updated_at)
    .execute(db.pool())
    .await?;
    Ok(())
}

async fn insert_route(db: &Db, r: &Route) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO routes \
         (id, tenant_id, name, node_id, type, enabled, listen_host, listen_port, hostname, \
          target_host, target_port, tls_mode, status, limits, created_at, updated_at) \
         VALUES (?, 'default', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&r.id)
    .bind(&r.name)
    .bind(&r.node_id)
    .bind(&r.route_type)
    .bind(r.enabled)
    .bind(r.listen_host.as_deref())
    .bind(r.listen_port)
    .bind(r.hostname.as_deref())
    .bind(&r.target_host)
    .bind(r.target_port)
    .bind(r.tls_mode.as_deref())
    .bind(&r.status)
    .bind(r.limits.as_deref())
    .bind(&r.created_at)
    .bind(&r.updated_at)
    .execute(db.pool())
    .await?;
    Ok(())
}

async fn insert_domain(db: &Db, d: &Domain) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO domains \
         (id, tenant_id, hostname, route_id, tls_mode, certificate_id, enabled, created_at, updated_at) \
         VALUES (?, 'default', ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&d.id)
    .bind(&d.hostname)
    .bind(d.route_id.as_deref())
    .bind(d.tls_mode.as_deref())
    .bind(d.certificate_id.as_deref())
    .bind(d.enabled)
    .bind(&d.created_at)
    .bind(&d.updated_at)
    .execute(db.pool())
    .await?;
    Ok(())
}

async fn insert_acl_rule(db: &Db, a: &AclRule) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO acl_rules \
         (id, tenant_id, route_id, action, source_cidr, source_port, target_host, target_port, created_at) \
         VALUES (?, 'default', ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&a.id)
    .bind(a.route_id.as_deref())
    .bind(&a.action)
    .bind(a.source_cidr.as_deref())
    .bind(a.source_port)
    .bind(a.target_host.as_deref())
    .bind(a.target_port)
    .bind(&a.created_at)
    .execute(db.pool())
    .await?;
    Ok(())
}

async fn insert_credential(db: &Db, c: &Credential) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO credentials \
         (id, node_id, type, secret_hash, expires_at, revoked_at, last_used_at, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&c.id)
    .bind(&c.node_id)
    .bind(&c.credential_type)
    .bind(&c.secret_hash)
    .bind(c.expires_at.as_deref())
    .bind(c.revoked_at.as_deref())
    .bind(c.last_used_at.as_deref())
    .bind(&c.created_at)
    .execute(db.pool())
    .await?;
    Ok(())
}

async fn insert_certificate(db: &Db, c: &Certificate) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO certificates \
         (id, tenant_id, name, hostnames, certificate, private_key_encrypted, expires_at, created_at, updated_at) \
         VALUES (?, 'default', ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&c.id)
    .bind(&c.name)
    .bind(&c.hostnames)
    .bind(&c.certificate)
    .bind(c.private_key_encrypted.as_deref())
    .bind(c.expires_at.as_deref())
    .bind(&c.created_at)
    .bind(&c.updated_at)
    .execute(db.pool())
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const NODE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa01";
    const CRED_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa02";
    const ROUTE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa03";
    const NOW: &str = "2026-08-27T00:00:00Z";

    async fn seeded_db() -> Db {
        let db = Db::connect_memory().await.unwrap();
        db.migrate().await.unwrap();
        db.create_node(NODE_ID, "demo-node", None, NOW)
            .await
            .unwrap();
        db.create_credential(CRED_ID, NODE_ID, "token", "deadbeef", None, NOW)
            .await
            .unwrap();
        db.create_route(
            ROUTE_ID,
            "demo-web",
            NODE_ID,
            "http",
            true,
            None,
            None,
            Some("app.example.com"),
            "target",
            5678,
            "none",
            None,
            NOW,
        )
        .await
        .unwrap();
        db
    }

    #[tokio::test]
    async fn backup_then_restore_roundtrips() {
        let db = seeded_db().await;
        let snap = Snapshot::from_db(&db, true).await.unwrap();
        assert_eq!(snap.nodes.len(), 1);
        assert_eq!(snap.routes.len(), 1);
        assert_eq!(snap.credentials.len(), 1);
        snap.validate().unwrap();

        // YAML 序列化往返。
        let yaml = snap.to_yaml().unwrap();
        let parsed = Snapshot::from_yaml(&yaml).unwrap();
        parsed.validate().unwrap();
        assert_eq!(parsed.credentials[0].secret_hash, "deadbeef");

        // 清库（模拟灾难恢复的「清库」）后恢复。
        let fresh = Db::connect_memory().await.unwrap();
        fresh.migrate().await.unwrap();
        let report = restore(&fresh, &parsed, true).await.unwrap();
        assert_eq!(report.nodes.inserted, 1);
        assert_eq!(report.routes.inserted, 1);
        assert_eq!(report.credentials.inserted, 1);

        // Agent 凭据仍可通过认证查询命中。
        let cred = fresh
            .find_credential_by_hash("deadbeef", "token")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cred.node_id, NODE_ID);
    }

    #[tokio::test]
    async fn export_excludes_credentials() {
        let db = seeded_db().await;
        let snap = Snapshot::from_db(&db, false).await.unwrap();
        assert_eq!(snap.nodes.len(), 1);
        assert_eq!(snap.routes.len(), 1);
        assert!(snap.credentials.is_empty());
        assert!(snap.certificates.is_empty());
        // 导出的 YAML 不含 secret_hash。
        let yaml = snap.to_yaml().unwrap();
        assert!(!yaml.contains("secret_hash"));
        assert!(!yaml.contains("deadbeef"));
    }

    #[tokio::test]
    async fn restore_is_idempotent_and_skips_existing() {
        let db = seeded_db().await;
        let snap = Snapshot::from_db(&db, true).await.unwrap();
        // 已存在的行全部跳过。
        let report = restore(&db, &snap, true).await.unwrap();
        assert_eq!(report.nodes.skipped, 1);
        assert_eq!(report.nodes.inserted, 0);
        assert_eq!(report.routes.skipped, 1);
        assert_eq!(report.credentials.skipped, 1);
    }

    #[tokio::test]
    async fn validate_rejects_dangling_route_node() {
        let mut snap = Snapshot {
            routes: vec![Route {
                id: "r1".into(),
                name: "r".into(),
                node_id: "missing".into(),
                route_type: "http".into(),
                enabled: true,
                listen_host: None,
                listen_port: None,
                hostname: None,
                target_host: "t".into(),
                target_port: 80,
                tls_mode: None,
                status: "draft".into(),
                limits: None,
                created_at: NOW.into(),
                updated_at: NOW.into(),
            }],
            ..Default::default()
        };
        assert!(snap.validate().is_err());

        // 补上 node 后通过。
        snap.nodes.push(Node {
            id: "missing".into(),
            name: "n".into(),
            description: None,
            status: "pending".into(),
            hostname: None,
            platform: None,
            architecture: None,
            agent_version: None,
            remote_addr: None,
            last_seen_at: None,
            connected_at: None,
            config_version: 0,
            applied_config_version: 0,
            config_status: "pending".into(),
            created_at: NOW.into(),
            updated_at: NOW.into(),
        });
        assert!(snap.validate().is_ok());
    }
}
