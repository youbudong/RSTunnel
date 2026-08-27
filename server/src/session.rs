//! Web 会话（T-20）：内存会话 + 短时访问 token。
//!
//! 设计文档 §69/§71：会话凭据走 HttpOnly Secure SameSite cookie（session id），另有短时
//! Bearer 访问 token 供 API/WebSocket 程序化调用；登录密码用 Argon2id（见 [`tunnel_auth`]）。
//! 会话与 token 均为高熵随机值（[`tunnel_auth::generate_token`]），内存 `DashMap` 存储；
//! HA 里程碑再迁 Redis/DB（设计文档 §159）。

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde::Serialize;
use tunnel_auth::generate_token;
use utoipa::ToSchema;

/// 会话（cookie `sid`）TTL：7 天。
pub const SESSION_TTL_SECS: i64 = 7 * 24 * 3600;
/// 短时访问 token TTL：15 分钟。
pub const ACCESS_TOKEN_TTL_SECS: i64 = 15 * 60;

/// 已登录用户（下发 /auth/me 与登录响应的最小画像）。
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct User {
    pub id: String,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub role: String,
}

#[derive(Debug, Clone)]
struct Session {
    user: User,
    expires_at: i64,
}

#[derive(Debug, Clone)]
struct AccessToken {
    session_id: String,
    expires_at: i64,
}

/// 登录签发的凭据：session id（写入 cookie）与短时访问 token。
#[derive(Debug, Clone)]
pub struct Issued {
    pub session_id: String,
    pub access_token: String,
}

/// 内存会话存储：`session id → 会话` 与 `访问 token → session id`。
#[derive(Debug, Default)]
pub struct SessionStore {
    sessions: DashMap<String, Session>,
    access_tokens: DashMap<String, AccessToken>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// 为某用户创建会话并签发短时访问 token。
    pub fn create(&self, user: User) -> Issued {
        let session_id = generate_token();
        let access_token = generate_token();
        let now = now_secs();
        self.sessions.insert(
            session_id.clone(),
            Session {
                user,
                expires_at: now + SESSION_TTL_SECS,
            },
        );
        self.access_tokens.insert(
            access_token.clone(),
            AccessToken {
                session_id: session_id.clone(),
                expires_at: now + ACCESS_TOKEN_TTL_SECS,
            },
        );
        Issued {
            session_id,
            access_token,
        }
    }

    /// 按 session id（cookie）取用户；不存在或已过期返回 `None`（过期即惰性清理）。
    pub fn user_by_session(&self, session_id: &str) -> Option<User> {
        let session = self.sessions.get(session_id)?;
        if session.expires_at <= now_secs() {
            drop(session);
            self.sessions.remove(session_id);
            return None;
        }
        Some(session.user.clone())
    }

    /// 按短时访问 token 取用户；不存在或已过期返回 `None`。
    pub fn user_by_access_token(&self, token: &str) -> Option<User> {
        let entry = self.access_tokens.get(token)?;
        if entry.expires_at <= now_secs() {
            drop(entry);
            self.access_tokens.remove(token);
            return None;
        }
        let session_id = entry.session_id.clone();
        drop(entry);
        self.user_by_session(&session_id)
    }

    /// 刷新：校验 session 未过期后签发新访问 token；session 失效返回 `None`。
    pub fn refresh(&self, session_id: &str) -> Option<String> {
        let session = self.sessions.get(session_id)?;
        if session.expires_at <= now_secs() {
            drop(session);
            self.sessions.remove(session_id);
            return None;
        }
        let access_token = generate_token();
        self.access_tokens.insert(
            access_token.clone(),
            AccessToken {
                session_id: session_id.to_string(),
                expires_at: now_secs() + ACCESS_TOKEN_TTL_SECS,
            },
        );
        Some(access_token)
    }

    /// 登出：删除会话及其全部访问 token。
    pub fn revoke(&self, session_id: &str) {
        self.sessions.remove(session_id);
        self.access_tokens
            .retain(|_, entry| entry.session_id != session_id);
    }
}

/// 当前 Unix 秒（会话 TTL 比较用；时钟异常时回退 0 以保证按过期处理，不 panic）。
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 共享会话存储句柄（`AppState` 持有，`Clone` 便于跨 handler）。
pub type SharedSessionStore = Arc<SessionStore>;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn user(name: &str) -> User {
        User {
            id: name.to_string(),
            username: name.to_string(),
            email: None,
            role: "admin".to_string(),
        }
    }

    #[test]
    fn create_issue_and_lookup_roundtrip() {
        let store = SessionStore::new();
        let issued = store.create(user("alice"));

        let by_session = store.user_by_session(&issued.session_id).unwrap();
        assert_eq!(by_session.username, "alice");

        let by_token = store.user_by_access_token(&issued.access_token).unwrap();
        assert_eq!(by_token.id, "alice");
    }

    #[test]
    fn refresh_issues_new_token() {
        let store = SessionStore::new();
        let issued = store.create(user("bob"));
        let new_token = store.refresh(&issued.session_id).unwrap();
        assert_ne!(new_token, issued.access_token);
        assert!(store.user_by_access_token(&new_token).is_some());
    }

    #[test]
    fn revoke_clears_session_and_tokens() {
        let store = SessionStore::new();
        let issued = store.create(user("carol"));
        store.revoke(&issued.session_id);
        assert!(store.user_by_session(&issued.session_id).is_none());
        assert!(store.user_by_access_token(&issued.access_token).is_none());
    }

    #[test]
    fn unknown_ids_are_none() {
        let store = SessionStore::new();
        assert!(store.user_by_session("nope").is_none());
        assert!(store.user_by_access_token("nope").is_none());
        assert!(store.refresh("nope").is_none());
    }
}
