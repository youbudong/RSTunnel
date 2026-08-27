//! Node CRUD（T-21）：`/api/v1/nodes` 全套 + 审计日志（设计文档 §21/§25/§40）。
//!
//! 写入操作（create/update/delete）各写一条 `audit_logs`；读操作仅要求登录。

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tunnel_auth::{generate_token, hash_token};
use utoipa::ToSchema;
use uuid::Uuid;

use super::auth::CurrentUser;
use super::rbac::{require_permission, Permission};
use super::{internal, map_db_error, now_rfc3339, write_audit, ApiError, AppState};
use crate::event::{NODE_CREATED, NODE_UPDATED};
use tunnel_db::NodeRow;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/nodes", get(list_nodes).post(create_node))
        .route(
            "/nodes/:id",
            get(get_node).patch(update_node).delete(delete_node),
        )
        .route("/nodes/:id/credentials", post(create_credential))
        .route(
            "/nodes/:id/credentials/:credential_id/revoke",
            post(revoke_credential),
        )
}

/// Node 响应对象（api.md §5）。
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct Node {
    id: String,
    name: String,
    description: Option<String>,
    status: String,
    hostname: Option<String>,
    platform: Option<String>,
    architecture: Option<String>,
    agent_version: Option<String>,
    remote_addr: Option<String>,
    connected_at: Option<String>,
    last_seen_at: Option<String>,
    config_version: i64,
    applied_config_version: i64,
    config_status: String,
}

fn node_response(row: NodeRow) -> Node {
    Node {
        id: row.id,
        name: row.name,
        description: row.description,
        status: row.status,
        hostname: row.hostname,
        platform: row.platform,
        architecture: row.architecture,
        agent_version: row.agent_version,
        remote_addr: row.remote_addr,
        connected_at: row.connected_at,
        last_seen_at: row.last_seen_at,
        config_version: row.config_version,
        applied_config_version: row.applied_config_version,
        config_status: row.config_status,
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct CreateNodeRequest {
    name: String,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct UpdateNodeRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

/// 创建 Node 的响应：`node` + 一次性 bootstrap token（明文仅此一次，§4/§94）。
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CreateNodeResponse {
    node: Node,
    bootstrap_token: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct CreateCredentialRequest {
    #[serde(rename = "type", default = "default_credential_type")]
    credential_type: String,
    #[serde(default)]
    expires_at: Option<String>,
}

fn default_credential_type() -> String {
    "token".to_string()
}

/// 新凭据响应：`token` 为明文，仅创建时返回一次（§71）。
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CredentialResponse {
    id: String,
    token: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/nodes",
    responses((status = 200, description = "List nodes", body = Vec<Node>)),
    tag = "nodes"
)]
async fn list_nodes(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
) -> Result<Response, ApiError> {
    require_permission(&user, Permission::NodesRead)?;
    let rows = state.db.list_nodes().await.map_err(internal)?;
    let nodes: Vec<Node> = rows.into_iter().map(node_response).collect();
    Ok(Json(nodes).into_response())
}

#[utoipa::path(
    get,
    path = "/api/v1/nodes/{id}",
    params(("id" = String, Path, description = "Node id")),
    responses(
        (status = 200, description = "Node detail", body = Node),
        (status = 404, description = "Node not found")
    ),
    tag = "nodes"
)]
async fn get_node(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    require_permission(&user, Permission::NodesRead)?;
    let node = state
        .db
        .get_node(&id)
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::not_found("NODE_NOT_FOUND", "node does not exist"))?;
    Ok(Json(node_response(node)).into_response())
}

#[utoipa::path(
    post,
    path = "/api/v1/nodes",
    request_body = CreateNodeRequest,
    responses(
        (status = 201, description = "Node created (bootstrap token shown once)", body = CreateNodeResponse),
        (status = 409, description = "Duplicate name")
    ),
    tag = "nodes"
)]
async fn create_node(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Json(body): Json<CreateNodeRequest>,
) -> Result<Response, ApiError> {
    require_permission(&user, Permission::NodesWrite)?;
    let name = body.name.trim().to_string();
    if name.is_empty() {
        return Err(ApiError::unprocessable(
            "INVALID_NAME",
            "name must not be empty",
        ));
    }
    if state
        .db
        .node_name_exists(&name, None)
        .await
        .map_err(internal)?
    {
        return Err(ApiError::conflict(
            "DUPLICATE_NAME",
            format!("node {name:?} already exists"),
        ));
    }

    let id = Uuid::new_v4().to_string();
    let ts = now_rfc3339();
    state
        .db
        .create_node(&id, &name, body.description.as_deref(), &ts)
        .await
        .map_err(|e| map_db_error(e, "node"))?;

    // §4/§94：创建时生成一次性 bootstrap token，明文仅此一次返回，DB 只存哈希。
    let bootstrap_token = generate_token();
    let bootstrap_id = Uuid::new_v4().to_string();
    state
        .db
        .create_credential(
            &bootstrap_id,
            &id,
            "bootstrap",
            &hash_token(&bootstrap_token),
            None,
            &ts,
        )
        .await
        .map_err(internal)?;

    let node = state
        .db
        .get_node(&id)
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::internal("node not found after create"))?;
    write_audit(
        &state,
        Some(&user.id),
        "node.create",
        "node",
        &id,
        Some(json!({ "name": name })),
    )
    .await?;
    state
        .events
        .publish(NODE_CREATED, json!({ "node_id": id, "name": name }));
    Ok((
        StatusCode::CREATED,
        Json(CreateNodeResponse {
            node: node_response(node),
            bootstrap_token,
        }),
    )
        .into_response())
}

#[utoipa::path(
    patch,
    path = "/api/v1/nodes/{id}",
    params(("id" = String, Path, description = "Node id")),
    request_body = UpdateNodeRequest,
    responses(
        (status = 200, description = "Node updated", body = Node),
        (status = 404, description = "Node not found")
    ),
    tag = "nodes"
)]
async fn update_node(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Path(id): Path<String>,
    Json(body): Json<UpdateNodeRequest>,
) -> Result<Response, ApiError> {
    require_permission(&user, Permission::NodesWrite)?;
    let existing = state
        .db
        .get_node(&id)
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::not_found("NODE_NOT_FOUND", "node does not exist"))?;

    let name = match body.name {
        Some(n) => {
            let n = n.trim().to_string();
            if n.is_empty() {
                return Err(ApiError::unprocessable(
                    "INVALID_NAME",
                    "name must not be empty",
                ));
            }
            n
        }
        None => existing.name.clone(),
    };
    // `None` = 不修改（v1 不支持置空 description）。
    let description = body.description.or(existing.description.clone());

    if name != existing.name
        && state
            .db
            .node_name_exists(&name, Some(&id))
            .await
            .map_err(internal)?
    {
        return Err(ApiError::conflict(
            "DUPLICATE_NAME",
            format!("node {name:?} already exists"),
        ));
    }

    let ts = now_rfc3339();
    state
        .db
        .update_node(&id, &name, description.as_deref(), &ts)
        .await
        .map_err(|e| map_db_error(e, "node"))?;

    let node = state
        .db
        .get_node(&id)
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::internal("node not found after update"))?;
    write_audit(
        &state,
        Some(&user.id),
        "node.update",
        "node",
        &id,
        Some(json!({ "name": name })),
    )
    .await?;
    state
        .events
        .publish(NODE_UPDATED, json!({ "node_id": id, "name": name }));
    Ok(Json(node_response(node)).into_response())
}

#[utoipa::path(
    delete,
    path = "/api/v1/nodes/{id}",
    params(("id" = String, Path, description = "Node id")),
    responses(
        (status = 204, description = "Node deleted"),
        (status = 404, description = "Node not found")
    ),
    tag = "nodes"
)]
async fn delete_node(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    require_permission(&user, Permission::NodesWrite)?;
    if !state.db.node_exists(&id).await.map_err(internal)? {
        return Err(ApiError::not_found("NODE_NOT_FOUND", "node does not exist"));
    }
    state.db.delete_node(&id).await.map_err(internal)?;
    write_audit(&state, Some(&user.id), "node.delete", "node", &id, None).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// 为 node 签发运行时凭据（§5/§71）。明文 token 仅此一次返回。
#[utoipa::path(
    post,
    path = "/api/v1/nodes/{id}/credentials",
    params(("id" = String, Path, description = "Node id")),
    request_body = CreateCredentialRequest,
    responses(
        (status = 201, description = "Credential created (token shown once)", body = CredentialResponse),
        (status = 404, description = "Node not found")
    ),
    tag = "nodes"
)]
async fn create_credential(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Path(node_id): Path<String>,
    Json(body): Json<CreateCredentialRequest>,
) -> Result<Response, ApiError> {
    require_permission(&user, Permission::NodesWrite)?;
    if body.credential_type != "token" {
        return Err(ApiError::unprocessable(
            "INVALID_TYPE",
            "only credential type 'token' is supported",
        ));
    }
    if let Some(exp) = &body.expires_at {
        if time::OffsetDateTime::parse(exp, &time::format_description::well_known::Rfc3339).is_err()
        {
            return Err(ApiError::unprocessable(
                "INVALID_EXPIRES_AT",
                "expires_at must be a valid RFC3339 timestamp",
            ));
        }
    }
    if !state.db.node_exists(&node_id).await.map_err(internal)? {
        return Err(ApiError::not_found("NODE_NOT_FOUND", "node does not exist"));
    }

    let id = Uuid::new_v4().to_string();
    let ts = now_rfc3339();
    let token = generate_token();
    state
        .db
        .create_credential(
            &id,
            &node_id,
            "token",
            &hash_token(&token),
            body.expires_at.as_deref(),
            &ts,
        )
        .await
        .map_err(internal)?;

    write_audit(
        &state,
        Some(&user.id),
        "credential.create",
        "credential",
        &id,
        Some(json!({ "type": "token" })),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(CredentialResponse { id, token })).into_response())
}

/// 吊销凭据（§71）：写 `revoked_at`，之后 Agent 无法认证。
#[utoipa::path(
    post,
    path = "/api/v1/nodes/{id}/credentials/{credential_id}/revoke",
    params(
        ("id" = String, Path, description = "Node id"),
        ("credential_id" = String, Path, description = "Credential id")
    ),
    responses(
        (status = 204, description = "Credential revoked"),
        (status = 404, description = "Credential not found")
    ),
    tag = "nodes"
)]
async fn revoke_credential(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Path((node_id, credential_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    require_permission(&user, Permission::NodesWrite)?;
    let cred = state
        .db
        .get_credential(&credential_id)
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::not_found("CREDENTIAL_NOT_FOUND", "credential does not exist"))?;
    if cred.node_id != node_id {
        return Err(ApiError::not_found(
            "CREDENTIAL_NOT_FOUND",
            "credential does not belong to node",
        ));
    }

    let ts = now_rfc3339();
    state
        .db
        .revoke_credential(&credential_id, &ts)
        .await
        .map_err(internal)?;
    write_audit(
        &state,
        Some(&user.id),
        "credential.revoke",
        "credential",
        &credential_id,
        None,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
