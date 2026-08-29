//! First-run 引导（T-20）：`users` 表为空时，Web 管理后台经 `/api/v1/setup`
//! 创建第一个管理员账户（`admin` 角色）。创建后该端点自锁（409）。

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tunnel_auth::hash_password;
use utoipa::ToSchema;
use uuid::Uuid;

use super::auth::{session_cookie, LoginResponse};
use super::{internal, map_db_error, now_rfc3339, write_audit, ApiError, AppState};
use crate::session::User;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/setup", get(setup_status).post(setup))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SetupStatusResponse {
    pub initialized: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetupRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub email: Option<String>,
}

/// 查询是否已初始化（`users` 表是否为空）。
#[utoipa::path(
    get,
    path = "/api/v1/setup",
    responses(
        (status = 200, description = "Setup status", body = SetupStatusResponse)
    ),
    tag = "setup"
)]
async fn setup_status(
    State(state): State<AppState>,
) -> Result<Json<SetupStatusResponse>, ApiError> {
    let n = state.db.count_users().await.map_err(internal)?;
    Ok(Json(SetupStatusResponse { initialized: n > 0 }))
}

/// 创建初始管理员：仅当系统尚无任何用户时可用；成功后直接签发会话（登录态）。
#[utoipa::path(
    post,
    path = "/api/v1/setup",
    request_body = SetupRequest,
    responses(
        (status = 200, description = "Initial admin created", body = LoginResponse),
        (status = 409, description = "Setup already done"),
        (status = 422, description = "Invalid username/password")
    ),
    tag = "setup"
)]
async fn setup(
    State(state): State<AppState>,
    Json(body): Json<SetupRequest>,
) -> Result<Response, ApiError> {
    // 首次引导自锁：一旦有任何用户，拒绝再次创建（并发下用户名唯一约束兜底）。
    if state.db.count_users().await.map_err(internal)? > 0 {
        return Err(ApiError::conflict(
            "SETUP_ALREADY_DONE",
            "initial admin already exists",
        ));
    }

    let username = body.username.trim().to_string();
    if username.is_empty() {
        return Err(ApiError::unprocessable(
            "INVALID_USERNAME",
            "username must not be empty",
        ));
    }
    if body.password.len() < 8 {
        return Err(ApiError::unprocessable(
            "WEAK_PASSWORD",
            "password must be at least 8 characters",
        ));
    }

    let id = Uuid::new_v4().to_string();
    let ts = now_rfc3339();
    let password_hash = hash_password(&body.password).map_err(internal)?;
    state
        .db
        .create_user(
            &id,
            &username,
            body.email.as_deref(),
            &password_hash,
            false,
            &ts,
        )
        .await
        .map_err(|e| map_db_error(e, "user"))?;

    // `admin` 角色由迁移（0003_seed_roles）保证存在。
    let role_id = state
        .db
        .find_role_id_by_name("admin")
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::internal("admin role missing (migration 0003 not applied)"))?;
    state
        .db
        .assign_user_role(&id, &role_id)
        .await
        .map_err(internal)?;

    let user = User {
        id: id.clone(),
        username,
        email: body.email,
        role: "admin".to_string(),
    };

    // 审计：机器触发的首次引导，user_id 传 None（同 enroll）。
    write_audit(
        &state,
        None,
        "user.create",
        "user",
        &id,
        Some(json!({ "setup": true, "role": "admin" })),
    )
    .await?;

    // 直接签发会话，前端创建后即进入登录态（复用 login 的响应形状）。
    let issued = state.sessions.create(user.clone());
    let payload = LoginResponse {
        user,
        access_token: issued.access_token,
        token_type: "Bearer",
    };
    let mut resp = Json(payload).into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, session_cookie(&issued.session_id));
    Ok(resp)
}
