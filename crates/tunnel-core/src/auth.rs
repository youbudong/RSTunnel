//! Node 认证：HELLO→AUTH→AUTH_OK 的服务端校验逻辑（docs/protocol.md §6.1）。
//!
//! 纯业务校验，不接触 wire/IO；token 哈希、DB 查询、时间比较都在此处完成，
//! Server 拿到 [`AuthDecision`] 后组包 AUTH_OK / AUTH_FAIL。

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tunnel_auth::hash_token;
use tunnel_db::{Db, NodeCredentialRow};
use tunnel_protocol::AuthPayload;
use uuid::Uuid;

/// 服务端支持的协议主版本号（docs/protocol.md §9：major 不兼容）。
pub const SUPPORTED_PROTOCOL_MAJOR: u16 = 1;

/// 认证成功后的 node 状态（供 AUTH_OK 组包）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthSuccess {
    pub node_id: Uuid,
    pub config_version: u64,
}

/// 认证结果：成功，或带协议层错误码的失败（docs/protocol.md §8）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthDecision {
    Success(AuthSuccess),
    Failure { code: &'static str, message: String },
}

impl AuthDecision {
    fn fail(code: &'static str, message: impl Into<String>) -> Self {
        AuthDecision::Failure {
            code,
            message: message.into(),
        }
    }
}

/// 校验 AUTH payload：token hash 命中 → 检查 revoked/expired/disabled → 返回结果。
///
/// `now` 由调用方注入（便于测试），用于判断 `expires_at` 是否过期。
pub async fn authenticate(db: &Db, payload: &AuthPayload, now: OffsetDateTime) -> AuthDecision {
    let credential = match payload.credential.as_deref() {
        Some(c) if !c.is_empty() => c,
        _ => return AuthDecision::fail("AUTH_FAILED", "missing credential"),
    };

    let hash = hash_token(credential);
    let row = match db.find_node_credential(&hash).await {
        Ok(Some(row)) => row,
        Ok(None) => return AuthDecision::fail("AUTH_FAILED", "invalid credential"),
        Err(e) => {
            tracing::error!(error = %e, "auth db query failed");
            return AuthDecision::fail("INTERNAL_ERROR", "db error");
        }
    };

    evaluate(row, payload.node_id, now)
}

/// 对已查得的 credential/node 行做纯内存校验（无 IO，便于单测覆盖各分支）。
fn evaluate(
    row: NodeCredentialRow,
    claimed_node: Option<Uuid>,
    now: OffsetDateTime,
) -> AuthDecision {
    let node_id = match Uuid::parse_str(&row.node_id) {
        Ok(id) => id,
        Err(e) => {
            tracing::error!(error = %e, node_id = %row.node_id, "invalid node id in db");
            return AuthDecision::fail("INTERNAL_ERROR", "invalid node id in db");
        }
    };

    if let Some(claimed) = claimed_node {
        if claimed != node_id {
            return AuthDecision::fail("AUTH_FAILED", "credential does not match node");
        }
    }

    if row.revoked_at.is_some() {
        return AuthDecision::fail("AUTH_FAILED", "credential revoked");
    }

    if let Some(expires) = &row.expires_at {
        match OffsetDateTime::parse(expires, &Rfc3339) {
            Ok(exp) if exp <= now => {
                return AuthDecision::fail("AUTH_FAILED", "credential expired")
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, expires_at = %expires, "invalid expires_at value");
                return AuthDecision::fail("AUTH_FAILED", "credential expired");
            }
        }
    }

    if row.node_status == "disabled" {
        return AuthDecision::fail("NODE_DISABLED", "node disabled");
    }

    AuthDecision::Success(AuthSuccess {
        node_id,
        config_version: row.config_version.max(0) as u64,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use tunnel_db::sqlx;
    use uuid::Uuid;

    const NODE_ID: &str = "11111111-1111-4111-8111-111111111111";
    const NOW: &str = "2026-08-27T12:00:00Z";

    fn now() -> OffsetDateTime {
        OffsetDateTime::parse(NOW, &Rfc3339).unwrap()
    }

    fn row(revoked_at: Option<&str>, expires_at: Option<&str>, status: &str) -> NodeCredentialRow {
        NodeCredentialRow {
            node_id: NODE_ID.to_string(),
            node_status: status.to_string(),
            config_version: 7,
            revoked_at: revoked_at.map(str::to_string),
            expires_at: expires_at.map(str::to_string),
        }
    }

    async fn seeded_db(token: &str) -> Db {
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
        sqlx::query(
            "INSERT INTO credentials (id, node_id, type, secret_hash, created_at) \
             VALUES (?, ?, 'token', ?, ?)",
        )
        .bind("22222222-2222-4222-8222-222222222222")
        .bind(NODE_ID)
        .bind(hash_token(token))
        .bind(NOW)
        .execute(db.pool())
        .await
        .unwrap();
        db
    }

    #[tokio::test]
    async fn correct_token_succeeds() {
        let db = seeded_db("secret-token").await;
        let payload = AuthPayload {
            node_id: None,
            credential: Some("secret-token".into()),
        };
        let expected_id = Uuid::parse_str(NODE_ID).unwrap();
        assert_eq!(
            authenticate(&db, &payload, now()).await,
            AuthDecision::Success(AuthSuccess {
                node_id: expected_id,
                config_version: 7,
            })
        );
    }

    #[tokio::test]
    async fn wrong_token_fails() {
        let db = seeded_db("secret-token").await;
        let payload = AuthPayload {
            node_id: None,
            credential: Some("nope".into()),
        };
        match authenticate(&db, &payload, now()).await {
            AuthDecision::Failure { code, .. } => assert_eq!(code, "AUTH_FAILED"),
            other => panic!("expected failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_credential_fails() {
        let db = seeded_db("secret-token").await;
        let payload = AuthPayload {
            node_id: None,
            credential: None,
        };
        match authenticate(&db, &payload, now()).await {
            AuthDecision::Failure { code, .. } => assert_eq!(code, "AUTH_FAILED"),
            other => panic!("expected failure, got {other:?}"),
        }
    }

    #[test]
    fn revoked_fails() {
        assert_eq!(
            evaluate(row(Some(NOW), None, "pending"), None, now()),
            AuthDecision::Failure {
                code: "AUTH_FAILED",
                message: "credential revoked".into(),
            }
        );
    }

    #[test]
    fn expired_fails() {
        assert_eq!(
            evaluate(
                row(None, Some("2020-01-01T00:00:00Z"), "pending"),
                None,
                now()
            ),
            AuthDecision::Failure {
                code: "AUTH_FAILED",
                message: "credential expired".into(),
            }
        );
    }

    #[test]
    fn future_expiry_succeeds() {
        let id = Uuid::parse_str(NODE_ID).unwrap();
        assert_eq!(
            evaluate(
                row(None, Some("2030-01-01T00:00:00Z"), "pending"),
                None,
                now()
            ),
            AuthDecision::Success(AuthSuccess {
                node_id: id,
                config_version: 7,
            })
        );
    }

    #[test]
    fn disabled_node_fails() {
        assert_eq!(
            evaluate(row(None, None, "disabled"), None, now()),
            AuthDecision::Failure {
                code: "NODE_DISABLED",
                message: "node disabled".into(),
            }
        );
    }

    #[test]
    fn mismatched_node_fails() {
        let other = Uuid::new_v4();
        assert_eq!(
            evaluate(row(None, None, "pending"), Some(other), now()),
            AuthDecision::Failure {
                code: "AUTH_FAILED",
                message: "credential does not match node".into(),
            }
        );
    }
}
