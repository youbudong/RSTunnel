//! 认证接口（T-20）：`/auth/login`、`/auth/logout`、`/auth/refresh`、`/auth/me`。
//!
//! 凭据模型（设计文档 §69）：登录校验 Argon2id 密码后签发会话——session id 走
//! HttpOnly Secure SameSite cookie，另返回短时 Bearer 访问 token；`/auth/me` 同时接受
//! cookie 或 `Authorization: Bearer`。登出吊销会话并清 cookie。

use async_trait::async_trait;
use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tunnel_auth::verify_password;
use utoipa::ToSchema;

use super::{internal, write_audit, ApiError, AppState};
use crate::session::{User, SESSION_TTL_SECS};

const SESSION_COOKIE: &str = "sid";

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LoginResponse {
    pub user: User,
    pub access_token: String,
    pub token_type: &'static str,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MeResponse {
    user: User,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RefreshResponse {
    access_token: String,
    token_type: &'static str,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/refresh", post(refresh))
        .route("/auth/me", get(me))
}

/// 登录：校验密码 → 建会话 → 设 cookie + 返回短时 token；错误凭据 401。
#[utoipa::path(
    post,
    path = "/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login success", body = LoginResponse),
        (status = 401, description = "Invalid credentials"),
        (status = 429, description = "Too many failed attempts (locked)")
    ),
    tag = "auth"
)]
async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginRequest>,
) -> Result<Response, ApiError> {
    // T-35：防暴力破解——窗口内失败达阈值后锁定该用户名，直接返回 429。
    if !state.login_limiter.allows(&body.username) {
        return Err(ApiError::too_many_requests(
            "LOGIN_LOCKED",
            "too many failed login attempts; try again later",
        ));
    }

    let row = state
        .db
        .find_user_by_username(&body.username)
        .await
        .map_err(internal)?;

    // 统一报错文案，避免泄露「用户是否存在」。任何失败都计入限速（防用户名枚举/爆破），
    // 并写审计（T-36）。审计写失败不遮蔽 401，故 best-effort。
    let Some(row) = row else {
        state.login_limiter.record_failure(&body.username);
        let _ = write_audit(
            &state,
            None,
            "login.failed",
            "user",
            &body.username,
            Some(json!({ "username": &body.username })),
        )
        .await;
        return Err(ApiError::unauthorized("invalid username or password"));
    };
    if row.disabled {
        state.login_limiter.record_failure(&body.username);
        let _ = write_audit(
            &state,
            Some(&row.id),
            "login.failed",
            "user",
            &row.id,
            Some(json!({ "username": &body.username })),
        )
        .await;
        return Err(ApiError::unauthorized("invalid username or password"));
    }
    let ok = verify_password(&body.password, &row.password_hash).map_err(internal)?;
    if !ok {
        state.login_limiter.record_failure(&body.username);
        let _ = write_audit(
            &state,
            Some(&row.id),
            "login.failed",
            "user",
            &row.id,
            Some(json!({ "username": &body.username })),
        )
        .await;
        return Err(ApiError::unauthorized("invalid username or password"));
    }

    // 成功即清除失败记录（滑动窗口重新开始）。
    state.login_limiter.reset(&body.username);

    let role = state
        .db
        .list_role_names_for_user(&row.id)
        .await
        .map_err(internal)?
        .into_iter()
        .next()
        .unwrap_or_else(|| "user".to_string());
    let user = User {
        id: row.id,
        username: row.username,
        email: row.email,
        role,
    };

    let issued = state.sessions.create(user.clone());
    // T-36：登录成功写审计（action=login）。审计失败按关键路径处理（与 CRUD 一致）。
    write_audit(&state, Some(&user.id), "login", "user", &user.id, None).await?;
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

/// 登出：吊销会话并清 cookie（幂等，未登录也返回 204）。
#[utoipa::path(
    post,
    path = "/auth/logout",
    responses((status = 204, description = "Logged out")),
    tag = "auth"
)]
async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let sid = cookie_value(&headers, SESSION_COOKIE);
    // T-36：登出前解析用户，写审计（best-effort——登出恒返回 204，审计失败不改变结果）。
    let user = sid.and_then(|sid| state.sessions.user_by_session(sid));
    if let Some(sid) = sid {
        state.sessions.revoke(sid);
    }
    if let Some(user) = user {
        let _ = write_audit(&state, Some(&user.id), "logout", "user", &user.id, None).await;
    }
    let mut resp = StatusCode::NO_CONTENT.into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, clear_cookie());
    resp
}

/// 刷新：校验 cookie 会话后签发新短时访问 token。
#[utoipa::path(
    post,
    path = "/auth/refresh",
    responses(
        (status = 200, description = "New access token", body = RefreshResponse),
        (status = 401, description = "Not authenticated")
    ),
    tag = "auth"
)]
async fn refresh(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    let Some(sid) = cookie_value(&headers, SESSION_COOKIE).map(str::to_owned) else {
        return Err(ApiError::unauthorized("not authenticated"));
    };
    let Some(access_token) = state.sessions.refresh(&sid) else {
        return Err(ApiError::unauthorized("session expired"));
    };
    Ok(Json(RefreshResponse {
        access_token,
        token_type: "Bearer",
    })
    .into_response())
}

/// 当前用户：cookie 或 Bearer token 任一有效即返回。
#[utoipa::path(
    get,
    path = "/auth/me",
    responses(
        (status = 200, description = "Current user", body = MeResponse),
        (status = 401, description = "Not authenticated")
    ),
    tag = "auth"
)]
async fn me(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    let Some(user) = current_user(&state, &headers) else {
        return Err(ApiError::unauthorized("not authenticated"));
    };
    Ok(Json(MeResponse { user }).into_response())
}

/// 从请求头解析当前用户（优先 Bearer token，其次 cookie）。
fn current_user(state: &AppState, headers: &HeaderMap) -> Option<User> {
    if let Some(token) = bearer_token(headers) {
        if let Some(user) = state.sessions.user_by_access_token(token) {
            return Some(user);
        }
    }
    let sid = cookie_value(headers, SESSION_COOKIE)?;
    state.sessions.user_by_session(sid)
}

/// 构造 HttpOnly Secure SameSite 会话 cookie（login 与 setup 复用）。
pub(crate) fn session_cookie(session_id: &str) -> HeaderValue {
    let value = format!(
        "{SESSION_COOKIE}={session_id}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={SESSION_TTL_SECS}"
    );
    // session_id 为 hex，恒为合法 header 值；此处失败即编程错误，用静态兜底避免 panic。
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static("sid="))
}

/// 清 cookie（Max-Age=0）。
fn clear_cookie() -> HeaderValue {
    HeaderValue::from_static("sid=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0")
}

/// 从 `Cookie` 头取某 cookie 的值（简单 `name=value; …` 解析，会话 id 为 hex 无需转义）。
fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|part| {
            let (key, value) = part.split_once('=')?;
            (key == name).then_some(value)
        })
}

/// 从 `Authorization: Bearer <token>` 取 token。
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
}

/// 认证提取器：从请求解析当前用户（优先 Bearer，其次 cookie），未认证返回 401。
///
/// 供 nodes/routes 等需要登录的管理端点复用（T-21 起）。
pub struct CurrentUser(pub User);

#[async_trait]
impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let user = current_user(state, &parts.headers)
            .ok_or_else(|| ApiError::unauthorized("not authenticated"))?;
        Ok(CurrentUser(user))
    }
}
