//! 审计查询 API（T-36，设计文档 §40/api.md §8）：`GET /api/v1/audit-logs`。
//!
//! 需 `audit.read` 权限（默认 `admin`/`viewer` 可读，`operator` 不可）。支持按 `user_id`、
//! `action` 过滤与 `limit`/`offset` 分页，按创建时间倒序返回。

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::auth::CurrentUser;
use super::rbac::{require_permission, Permission};
use super::{internal, ApiError, AppState};
use tunnel_db::AuditRow;

pub fn router() -> Router<AppState> {
    Router::new().route("/audit-logs", get(list_audit_logs))
}

/// 默认分页大小（无 `limit` 参数时）。
const DEFAULT_LIMIT: i64 = 100;

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct AuditQuery {
    /// 按触发操作的用户 id 过滤。
    #[serde(default)]
    user_id: Option<String>,
    /// 按操作码过滤（如 `route.create`）。
    #[serde(default)]
    action: Option<String>,
    /// 返回条数上限（1..=1000）。
    #[serde(default = "default_limit")]
    limit: i64,
    /// 分页偏移。
    #[serde(default)]
    offset: i64,
}

fn default_limit() -> i64 {
    DEFAULT_LIMIT
}

/// 单条审计日志。`metadata` 为原始 JSON 文本（NULL = 无）。
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AuditEntry {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<String>,
    created_at: String,
}

fn audit_entry(row: AuditRow) -> AuditEntry {
    AuditEntry {
        id: row.id,
        user_id: row.user_id,
        action: row.action,
        resource_type: row.resource_type,
        resource_id: row.resource_id,
        ip: row.ip,
        user_agent: row.user_agent,
        metadata: row.metadata,
        created_at: row.created_at,
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/audit-logs",
    params(
        ("user_id" = Option<String>, Query, description = "Filter by user id"),
        ("action" = Option<String>, Query, description = "Filter by action"),
        ("limit" = Option<i64>, Query, description = "Max entries (1..=1000, default 100)"),
        ("offset" = Option<i64>, Query, description = "Pagination offset")
    ),
    responses((status = 200, description = "Audit log entries", body = Vec<AuditEntry>)),
    tag = "audit"
)]
async fn list_audit_logs(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Query(q): Query<AuditQuery>,
) -> Result<Response, ApiError> {
    require_permission(&user, Permission::AuditRead)?;
    let limit = q.limit.clamp(1, 1000);
    let offset = q.offset.max(0);
    let rows = state
        .db
        .list_audit_logs(q.user_id.as_deref(), q.action.as_deref(), limit, offset)
        .await
        .map_err(internal)?;
    let entries: Vec<AuditEntry> = rows.into_iter().map(audit_entry).collect();
    Ok(Json(entries).into_response())
}
