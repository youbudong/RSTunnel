//! Enrollment（T-22，§4/§21/§94）：Agent 用 bootstrap token 换取运行时凭据。
//!
//! 无需登录；凭据为一次性 bootstrap token（node 创建时签发）。成功后：
//! bootstrap token 作废、Agent 元数据合并进 node、签发运行时 token（明文仅此一次）。

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tunnel_auth::{generate_token, hash_token};
use utoipa::ToSchema;
use uuid::Uuid;

use super::{internal, now_rfc3339, write_audit, ApiError, AppState};

pub fn router() -> Router<AppState> {
    Router::new().route("/enroll", post(enroll))
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct EnrollRequest {
    bootstrap_token: String,
    #[serde(default)]
    node_name: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    platform: Option<String>,
    #[serde(default)]
    architecture: Option<String>,
    #[serde(default)]
    agent_version: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct EnrollResponse {
    node_id: String,
    credential: String,
    config_version: i64,
}

#[utoipa::path(
    post,
    path = "/enroll",
    request_body = EnrollRequest,
    responses(
        (status = 200, description = "Enrolled; runtime credential shown once", body = EnrollResponse),
        (status = 401, description = "Invalid or used bootstrap token"),
        (status = 422, description = "node_name mismatch or empty token")
    ),
    tag = "enroll"
)]
async fn enroll(
    State(state): State<AppState>,
    Json(body): Json<EnrollRequest>,
) -> Result<Response, ApiError> {
    let token = body.bootstrap_token.trim();
    if token.is_empty() {
        return Err(ApiError::unprocessable(
            "INVALID_TOKEN",
            "bootstrap_token must not be empty",
        ));
    }

    // 仅 bootstrap 类型可 enroll；运行时 token 走数据面 AUTH，不在此处。
    let cred = state
        .db
        .find_credential_by_hash(&hash_token(token), "bootstrap")
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::unauthorized("invalid bootstrap token"))?;

    if cred.revoked_at.is_some() {
        return Err(ApiError::unauthorized(
            "bootstrap token already used or revoked",
        ));
    }

    let node = state
        .db
        .get_node(&cred.node_id)
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::internal("bootstrap token references a missing node"))?;

    // `node_name`（若提供）作一次软校验，避免 Agent 拿错 token。
    if let Some(claimed) = body.node_name.as_deref().map(str::trim) {
        if !claimed.is_empty() && claimed != node.name {
            return Err(ApiError::unprocessable(
                "NODE_NAME_MISMATCH",
                "node_name does not match bootstrap token",
            ));
        }
    }

    let ts = now_rfc3339();

    // 一次性：作废 bootstrap token。
    state
        .db
        .revoke_credential(&cred.id, &ts)
        .await
        .map_err(internal)?;

    // 合并 Agent 上报的元数据。
    state
        .db
        .set_node_agent_meta(
            &node.id,
            body.hostname.as_deref(),
            body.platform.as_deref(),
            body.architecture.as_deref(),
            body.agent_version.as_deref(),
            &ts,
        )
        .await
        .map_err(internal)?;

    // 签发运行时凭据（明文仅此一次）。
    let runtime = generate_token();
    let runtime_id = Uuid::new_v4().to_string();
    state
        .db
        .create_credential(
            &runtime_id,
            &node.id,
            "token",
            &hash_token(&runtime),
            None,
            &ts,
        )
        .await
        .map_err(internal)?;

    // 审计：机器触发，user_id 为 None。
    write_audit(
        &state,
        None,
        "credential.revoke",
        "credential",
        &cred.id,
        Some(json!({ "reason": "enroll" })),
    )
    .await?;
    write_audit(
        &state,
        None,
        "credential.create",
        "credential",
        &runtime_id,
        Some(json!({ "type": "token", "via": "enroll" })),
    )
    .await?;

    Ok(Json(EnrollResponse {
        node_id: node.id,
        credential: runtime,
        config_version: node.config_version,
    })
    .into_response())
}
