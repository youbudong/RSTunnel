//! REST API（M6，§21）：axum 路由与共享状态。
//!
//! 统一错误格式见设计文档 §22：
//! `{ "error": { "code", "message", "request_id" } }`。

pub mod acl;
pub mod audit;
pub mod auth;
pub mod enroll;
pub mod health;
pub mod metrics;
pub mod nodes;
pub mod openapi;
pub mod rbac;
pub mod routes;
pub mod ws;

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Router;
use serde::Serialize;
use tunnel_db::Db;

use crate::acl_store::AclStore;
use crate::event::EventBus;
use crate::login_limiter::LoginLimiter;
use crate::readiness::Readiness;
use crate::session::SessionStore;

/// API 共享状态（handler 通过 [`axum::extract::State`] 注入）。
#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub sessions: Arc<SessionStore>,
    pub events: Arc<EventBus>,
    /// 数据面 ACL 判定器（与 main 中 Tcp/Http/Udp proxy 共享；REST 变更后 `reload` 热生效）。
    pub acl: Arc<AclStore>,
    /// 登录防暴力破解限速器（T-35：按用户名锁定，超限返回 429）。
    pub login_limiter: Arc<LoginLimiter>,
    /// SSRF 目标校验开关（T-37）：`true` 时允许 Route 目标指向 loopback/link-local/
    /// multicast/metadata 等危险地址；默认 `false`（拒绝）。来自 `[security]` 配置。
    pub allow_unsafe_targets: bool,
    /// 就绪状态（T-39/§98）：`/ready` 据此判定 DB/配置/QUIC/HTTP 是否就绪。
    pub readiness: Arc<Readiness>,
}

impl AppState {
    /// 独立（测试/单进程）构造：新建一个私有事件总线与空 ACL store。
    /// 默认全部就绪（无启动流程需要逐个置位）。
    pub fn new(db: Db) -> Self {
        Self::new_with_events(db, Arc::new(EventBus::new(EventBus::DEFAULT_CAPACITY)))
            .with_readiness(Arc::new(Readiness::ready()))
    }

    /// 与 QUIC 数据面共享同一事件总线（生产 main 用），保证 node online/offline
    /// 等数据面事件与 REST CRUD 事件都能推给 `/ws` 订阅者。
    pub fn new_with_events(db: Db, events: Arc<EventBus>) -> Self {
        Self::new_with_events_and_acl(db, events, Arc::new(AclStore::new()))
    }

    /// 与 QUIC 数据面共享同一事件总线与同一 ACL store（生产 main 用）。
    pub fn new_with_events_and_acl(db: Db, events: Arc<EventBus>, acl: Arc<AclStore>) -> Self {
        Self::new_with_events_acl_and_login(db, events, acl, Arc::new(LoginLimiter::default()))
    }

    /// 与 QUIC 数据面共享事件总线 + ACL store + 登录限速器（生产 main 用，参数来自配置）。
    pub fn new_with_events_acl_and_login(
        db: Db,
        events: Arc<EventBus>,
        acl: Arc<AclStore>,
        login_limiter: Arc<LoginLimiter>,
    ) -> Self {
        Self {
            db,
            sessions: Arc::new(SessionStore::new()),
            events,
            acl,
            login_limiter,
            allow_unsafe_targets: false,
            readiness: Arc::new(Readiness::new()),
        }
    }

    /// 覆盖 SSRF 目标校验开关（T-37）。生产 main 从 `[security]` 配置读取。
    pub fn with_allow_unsafe_targets(mut self, allow: bool) -> Self {
        self.allow_unsafe_targets = allow;
        self
    }

    /// 注入共享的就绪状态（T-39）。生产 main 用与启动流程相同的 `Arc`，逐组件 `mark_*`。
    pub fn with_readiness(mut self, readiness: Arc<Readiness>) -> Self {
        self.readiness = readiness;
        self
    }
}

/// 组装全部 API 路由：`/auth/*`（无前缀）+ `/api/v1/{nodes,routes}`（§21）。
///
/// 返回 `Router<()>`（已提供状态），可直接 `axum::serve` 或 `tower::ServiceExt::oneshot`
/// 测试（axum 0.7 仅 `Router<()>` 实现 `Service`，见其 `with_state` 文档）。
pub fn router(state: AppState) -> Router<()> {
    Router::new()
        .merge(auth::router())
        .merge(enroll::router())
        .merge(health::router())
        .merge(metrics::router())
        .merge(openapi::router())
        .merge(ws::router())
        .nest(
            "/api/v1",
            nodes::router()
                .merge(routes::router())
                .merge(acl::router())
                .merge(audit::router()),
        )
        .with_state(state)
}

/// RFC3339 UTC 时间戳（DB 时间戳约定，见 schema.md）。`time` 已为 workspace 依赖。
pub fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc().to_string()
}

/// API 错误（§22）。`code` 为稳定机器可读码，`message` 为人类可读描述。
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: ErrorDetail<'a>,
}

#[derive(Serialize)]
struct ErrorDetail<'a> {
    code: &'static str,
    message: &'a str,
}

impl ApiError {
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "UNAUTHORIZED",
            message: message.into(),
        }
    }

    /// 已认证但权限不足（RBAC，T-33）。
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "FORBIDDEN",
            message: message.into(),
        }
    }

    pub fn not_found(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code,
            message: message.into(),
        }
    }

    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code,
            message: message.into(),
        }
    }

    pub fn unprocessable(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code,
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "INTERNAL",
            message: message.into(),
        }
    }

    /// 限速/锁定（T-35）：登录失败超限、Route 超连接数等返回 429。
    pub fn too_many_requests(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = serde_json::to_string(&ErrorBody {
            error: ErrorDetail {
                code: self.code,
                message: &self.message,
            },
        });
        let body = body.unwrap_or_else(|_| "{}".to_string());
        let mut resp = (self.status, body).into_response();
        resp.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );
        resp
    }
}

/// 将底层错误（DB/argon2/header 等）包装为 500。
pub fn internal<E: std::fmt::Display>(e: E) -> ApiError {
    ApiError::internal(e.to_string())
}

/// 将 DB 错误映射为 API 错误：唯一约束冲突 → 409，其余 → 500。
///
/// `resource` 为冲突资源类型名（如 `route`/`node`），用于稳定错误码。
pub fn map_db_error(e: tunnel_db::sqlx::Error, resource: &'static str) -> ApiError {
    if let tunnel_db::sqlx::Error::Database(db) = &e {
        if db.is_unique_violation() {
            return ApiError::conflict(
                "DUPLICATE",
                format!("{resource} already exists (unique constraint violated)"),
            );
        }
    }
    ApiError::internal(e.to_string())
}

/// 写一条审计日志（设计文档 §40）。`metadata` 为可选的变更上下文 JSON。
///
/// 记录 `user_id`（当前登录用户；机器触发的操作如 `/enroll` 传 `None`）、`action`
/// （如 `route.create`）、资源类型与 id。`ip`/`user_agent` 留空，待 T-24 接入
/// `ConnectInfo`/真实请求头后补全。
pub(crate) async fn write_audit(
    state: &AppState,
    user_id: Option<&str>,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    metadata: Option<serde_json::Value>,
) -> Result<(), ApiError> {
    let id = uuid::Uuid::new_v4().to_string();
    let ts = now_rfc3339();
    let meta = metadata.as_ref().map(serde_json::Value::to_string);
    state
        .db
        .insert_audit_log(
            &id,
            user_id,
            action,
            resource_type,
            resource_id,
            None,
            None,
            meta.as_deref(),
            &ts,
        )
        .await
        .map_err(internal)?;
    Ok(())
}
