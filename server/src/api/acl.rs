//! ACL 管理面（T-34，api.md §7）：`/api/v1/acl-rules` 的 GET/POST/DELETE。
//!
//! 规则字段（§30/§1400）：`action`（allow/deny）+ 四维匹配 `source_cidr`/`source_port`/
//! `target_host`/`target_port`；`route_id` 为空表示全局规则。数据面匹配与默认 deny 见
//! [`tunnel_core::evaluate_acl`]（本层只做 CRUD + 校验 + 审计）。

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

use super::auth::CurrentUser;
use super::rbac::{require_permission, Permission};
use super::{internal, now_rfc3339, write_audit, ApiError, AppState};
use tunnel_common::cidr::parse_cidr;
use tunnel_db::AclRuleRow;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/acl-rules", get(list_acl_rules).post(create_acl_rule))
        .route("/acl-rules/:id", post(delete_acl_rule))
}

/// ACL 规则响应（api.md §7）。
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AclRule {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    route_id: Option<String>,
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_cidr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_port: Option<u16>,
}

fn rule_response(row: AclRuleRow) -> AclRule {
    AclRule {
        id: row.id,
        route_id: row.route_id,
        action: row.action,
        source_cidr: row.source_cidr,
        source_port: row.source_port.and_then(|p| u16::try_from(p).ok()),
        target_host: row.target_host,
        target_port: row.target_port.and_then(|p| u16::try_from(p).ok()),
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct CreateAclRuleRequest {
    #[serde(default)]
    route_id: Option<String>,
    action: String,
    #[serde(default)]
    source_cidr: Option<String>,
    #[serde(default)]
    source_port: Option<u16>,
    #[serde(default)]
    target_host: Option<String>,
    #[serde(default)]
    target_port: Option<u16>,
}

#[utoipa::path(
    get,
    path = "/api/v1/acl-rules",
    responses((status = 200, description = "List ACL rules", body = Vec<AclRule>)),
    tag = "acl"
)]
async fn list_acl_rules(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
) -> Result<Response, ApiError> {
    require_permission(&user, Permission::RoutesRead)?;
    let rows = state.db.list_acl_rules().await.map_err(internal)?;
    let rules: Vec<AclRule> = rows.into_iter().map(rule_response).collect();
    Ok(Json(rules).into_response())
}

#[utoipa::path(
    post,
    path = "/api/v1/acl-rules",
    request_body = CreateAclRuleRequest,
    responses(
        (status = 201, description = "ACL rule created", body = AclRule),
        (status = 422, description = "Invalid rule")
    ),
    tag = "acl"
)]
async fn create_acl_rule(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Json(body): Json<CreateAclRuleRequest>,
) -> Result<Response, ApiError> {
    require_permission(&user, Permission::RoutesWrite)?;

    let action = body.action.trim().to_ascii_lowercase();
    if action != "allow" && action != "deny" {
        return Err(ApiError::unprocessable(
            "INVALID_ACTION",
            "action must be 'allow' or 'deny'",
        ));
    }
    // source_cidr 必须是合法 CIDR / 裸 IP（非法即 422，§57 ACL 合法）。
    if let Some(cidr) = body.source_cidr.as_deref() {
        if parse_cidr(cidr).is_none() {
            return Err(ApiError::unprocessable(
                "INVALID_CIDR",
                format!("source_cidr {cidr:?} is not a valid CIDR"),
            ));
        }
    }
    // route_id 若指定须存在。
    if let Some(route_id) = body.route_id.as_deref() {
        if state
            .db
            .get_route(route_id)
            .await
            .map_err(internal)?
            .is_none()
        {
            return Err(ApiError::not_found(
                "ROUTE_NOT_FOUND",
                "route_id does not exist",
            ));
        }
    }

    let id = Uuid::new_v4().to_string();
    let ts = now_rfc3339();
    state
        .db
        .create_acl_rule(
            &id,
            body.route_id.as_deref(),
            &action,
            body.source_cidr.as_deref(),
            body.source_port.map(i64::from),
            body.target_host.as_deref(),
            body.target_port.map(i64::from),
            &ts,
        )
        .await
        .map_err(internal)?;

    write_audit(
        &state,
        Some(&user.id),
        "acl.create",
        "acl_rule",
        &id,
        Some(json!({ "action": action, "route_id": body.route_id })),
    )
    .await?;

    // 数据面热生效：让 AclStore 重新加载（若已接入；测试态为空 store 亦安全）。
    state.acl.reload(&state.db).await;

    let row = state
        .db
        .get_acl_rule(&id)
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::internal("acl rule not found after create"))?;
    Ok((StatusCode::CREATED, Json(rule_response(row))).into_response())
}

#[utoipa::path(
    post,
    path = "/api/v1/acl-rules/{id}",
    params(("id" = String, Path, description = "ACL rule id")),
    responses(
        (status = 204, description = "ACL rule deleted"),
        (status = 404, description = "ACL rule not found")
    ),
    tag = "acl"
)]
async fn delete_acl_rule(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    require_permission(&user, Permission::RoutesWrite)?;
    if state
        .db
        .get_acl_rule(&id)
        .await
        .map_err(internal)?
        .is_none()
    {
        return Err(ApiError::not_found(
            "ACL_RULE_NOT_FOUND",
            "acl rule does not exist",
        ));
    }
    state.db.delete_acl_rule(&id).await.map_err(internal)?;
    write_audit(&state, Some(&user.id), "acl.delete", "acl_rule", &id, None).await?;
    state.acl.reload(&state.db).await;
    Ok(StatusCode::NO_CONTENT.into_response())
}
