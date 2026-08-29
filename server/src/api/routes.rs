//! Route CRUD（T-21）：`/api/v1/routes` 全套 + 创建/更新校验（设计文档 §57）+ 审计日志。
//!
//! 校验规则：type 合法、端口范围、TCP/UDP 需 listen、HTTP/HTTPS 需 hostname、
//! node 存在、重复 listen / hostname / name 冲突（409），语义错误（端口/格式）返回 422。

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tunnel_common::target::forbidden_target_category;
use tunnel_db::{Db, RouteDetailRow};
use tunnel_protocol::{Limits, RouteType};
use utoipa::ToSchema;
use uuid::Uuid;

use super::auth::CurrentUser;
use super::rbac::{require_permission, Permission};
use super::{internal, map_db_error, now_rfc3339, write_audit, ApiError, AppState};
use crate::event::{CONFIG_UPDATED, ROUTE_CREATED, ROUTE_DELETED, ROUTE_UPDATED};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/routes", get(list_routes).post(create_route))
        .route(
            "/routes/:id",
            get(get_route).patch(update_route).delete(delete_route),
        )
        .route("/routes/:id/enable", post(enable_route))
        .route("/routes/:id/disable", post(disable_route))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TlsMode {
    Terminate,
    Passthrough,
    Disabled,
}

/// Route 响应对象（api.md §6）。
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct Route {
    id: String,
    name: String,
    node_id: String,
    #[serde(rename = "type")]
    route_type: RouteType,
    enabled: bool,
    listen_host: Option<String>,
    listen_port: Option<u16>,
    hostname: Option<String>,
    target_host: String,
    target_port: u16,
    tls_mode: Option<String>,
    status: String,
    limits: Option<Limits>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct CreateRouteRequest {
    name: String,
    node_id: String,
    #[serde(rename = "type")]
    route_type: RouteType,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    listen_host: Option<String>,
    #[serde(default)]
    listen_port: Option<u16>,
    #[serde(default)]
    hostname: Option<String>,
    target_host: String,
    target_port: u16,
    #[serde(default)]
    tls_mode: Option<TlsMode>,
    #[serde(default)]
    limits: Option<Limits>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct UpdateRouteRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    node_id: Option<String>,
    #[serde(rename = "type", default)]
    route_type: Option<RouteType>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    listen_host: Option<String>,
    #[serde(default)]
    listen_port: Option<u16>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    target_host: Option<String>,
    #[serde(default)]
    target_port: Option<u16>,
    #[serde(default)]
    tls_mode: Option<TlsMode>,
    #[serde(default)]
    limits: Option<Limits>,
}

fn default_true() -> bool {
    true
}

/// 归一化后的 Route 输入（校验通过后直接落库）。
struct RouteInput {
    name: String,
    node_id: String,
    route_type: RouteType,
    enabled: bool,
    listen_host: Option<String>,
    listen_port: Option<u16>,
    hostname: Option<String>,
    target_host: String,
    target_port: u16,
    tls_mode: TlsMode,
    limits: Option<Limits>,
}

fn route_type_str(t: RouteType) -> &'static str {
    match t {
        RouteType::Tcp => "tcp",
        RouteType::Udp => "udp",
        RouteType::Http => "http",
        RouteType::Https => "https",
    }
}

fn parse_route_type(s: &str) -> Option<RouteType> {
    match s {
        "tcp" => Some(RouteType::Tcp),
        "udp" => Some(RouteType::Udp),
        "http" => Some(RouteType::Http),
        "https" => Some(RouteType::Https),
        _ => None,
    }
}

fn tls_mode_str(t: TlsMode) -> &'static str {
    match t {
        TlsMode::Terminate => "terminate",
        TlsMode::Passthrough => "passthrough",
        TlsMode::Disabled => "disabled",
    }
}

fn parse_tls_mode(s: Option<&str>) -> Option<TlsMode> {
    match s {
        Some("terminate") => Some(TlsMode::Terminate),
        Some("passthrough") => Some(TlsMode::Passthrough),
        Some("disabled") => Some(TlsMode::Disabled),
        _ => None,
    }
}

/// 静态校验 + 归一化（不含 DB 冲突检查，见 [`check_conflicts`]）。
#[allow(clippy::too_many_arguments)]
fn normalize(
    name: String,
    node_id: String,
    route_type: RouteType,
    enabled: bool,
    listen_host: Option<String>,
    listen_port: Option<u16>,
    hostname: Option<String>,
    target_host: String,
    target_port: u16,
    tls_mode: Option<TlsMode>,
    limits: Option<Limits>,
) -> Result<RouteInput, ApiError> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err(ApiError::unprocessable(
            "INVALID_NAME",
            "name must not be empty",
        ));
    }
    if node_id.trim().is_empty() {
        return Err(ApiError::unprocessable(
            "INVALID_NODE",
            "node_id must not be empty",
        ));
    }
    if target_host.trim().is_empty() {
        return Err(ApiError::unprocessable(
            "INVALID_TARGET",
            "target_host must not be empty",
        ));
    }
    if target_port == 0 {
        return Err(ApiError::unprocessable(
            "INVALID_PORT",
            "target_port must be 1-65535",
        ));
    }
    let tls_mode = tls_mode.unwrap_or(TlsMode::Disabled);

    let (listen_host, listen_port, hostname) = match route_type {
        RouteType::Tcp | RouteType::Udp => {
            if hostname.is_some() {
                return Err(ApiError::unprocessable(
                    "INVALID_HOSTNAME",
                    "hostname is only valid for http/https routes",
                ));
            }
            let host = listen_host.unwrap_or_else(|| "0.0.0.0".to_string());
            if host.parse::<std::net::IpAddr>().is_err() {
                return Err(ApiError::unprocessable(
                    "INVALID_LISTEN",
                    "listen_host must be a valid IP address",
                ));
            }
            let port = listen_port.ok_or_else(|| {
                ApiError::unprocessable(
                    "INVALID_LISTEN",
                    "listen_port is required for tcp/udp routes",
                )
            })?;
            if port == 0 {
                return Err(ApiError::unprocessable(
                    "INVALID_PORT",
                    "listen_port must be 1-65535",
                ));
            }
            (Some(host), Some(port), None)
        }
        RouteType::Http | RouteType::Https => {
            let hostname = hostname
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    ApiError::unprocessable(
                        "INVALID_HOSTNAME",
                        "hostname is required for http/https routes",
                    )
                })?
                .to_string();
            if listen_host.is_some() || listen_port.is_some() {
                return Err(ApiError::unprocessable(
                    "INVALID_LISTEN",
                    "listen_host/listen_port are not used for http/https routes",
                ));
            }
            (None, None, Some(hostname))
        }
    };

    Ok(RouteInput {
        name,
        node_id,
        route_type,
        enabled,
        listen_host,
        listen_port,
        hostname,
        target_host,
        target_port,
        tls_mode,
        limits,
    })
}

/// SSRF 目标地址校验（T-37/§106）：`target_host` 为 IP 字面量时拒绝 loopback/link-local/
/// multicast/metadata；主机名不做解析（交由 Agent 运行时目标 ACL，T-34f）。`allow` 为
/// `security.allow_unsafe_targets`，置 true 即跳过校验（管理员显式放行）。
fn check_target(target_host: &str, allow: bool) -> Result<(), ApiError> {
    if allow {
        return Ok(());
    }
    let Ok(ip) = target_host.trim().parse::<std::net::IpAddr>() else {
        return Ok(());
    };
    if let Some(category) = forbidden_target_category(ip) {
        return Err(ApiError::unprocessable(
            "FORBIDDEN_TARGET",
            format!(
                "target {target_host} is forbidden ({category}); \
                 set security.allow_unsafe_targets to allow it"
            ),
        ));
    }
    Ok(())
}

/// DB 冲突检查：node 存在、name/hostname/listen 不重复（§57）。
async fn check_conflicts(
    db: &Db,
    input: &RouteInput,
    exclude_id: Option<&str>,
) -> Result<(), ApiError> {
    if !db.node_exists(&input.node_id).await.map_err(internal)? {
        return Err(ApiError::not_found(
            "NODE_NOT_FOUND",
            format!("node {} does not exist", input.node_id),
        ));
    }
    if db
        .route_name_exists(&input.name, exclude_id)
        .await
        .map_err(internal)?
    {
        return Err(ApiError::conflict(
            "DUPLICATE_NAME",
            format!("route {:?} already exists", input.name),
        ));
    }
    if let (Some(host), Some(port)) = (&input.listen_host, input.listen_port) {
        if db
            .route_listen_exists(host, i64::from(port), exclude_id)
            .await
            .map_err(internal)?
        {
            return Err(ApiError::conflict(
                "DUPLICATE_LISTEN",
                format!("listen {host}:{port} already in use"),
            ));
        }
    }
    if let Some(hostname) = &input.hostname {
        if db
            .route_hostname_exists(hostname, exclude_id)
            .await
            .map_err(internal)?
        {
            return Err(ApiError::conflict(
                "DUPLICATE_HOSTNAME",
                format!("hostname {hostname:?} already in use"),
            ));
        }
    }
    Ok(())
}

/// §28：路由变更后使受影响 Node 的 config_version +1（`config_status='pending'`），
/// 并立即向在线 Agent 推送全量路由快照（无需重连即收敛）；离线 Node 仅版本 +1，
/// 待重连时由握手快照收敛。
async fn bump_and_push(state: &AppState, node_id: &str) {
    let ts = now_rfc3339();
    let version = match state.db.bump_config_version(node_id, &ts).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(node_id = node_id, error = %e, "bump config_version failed");
            return;
        }
    };
    let Ok(node) = Uuid::parse_str(node_id) else {
        tracing::warn!(node_id = node_id, "invalid node id, skip config push");
        return;
    };
    if let Err(e) = state
        .config_sync
        .push_snapshot(&state.db, node, version.max(0) as u64)
        .await
    {
        tracing::warn!(node_id = node_id, error = %e, "push config snapshot failed");
    }
}

fn route_response(row: RouteDetailRow) -> Route {
    let route_type = parse_route_type(&row.route_type).unwrap_or(RouteType::Tcp);
    let limits = row
        .limits
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok());
    Route {
        id: row.id,
        name: row.name,
        node_id: row.node_id,
        route_type,
        enabled: row.enabled,
        listen_host: row.listen_host,
        listen_port: row.listen_port.map(|p| p as u16),
        hostname: row.hostname,
        target_host: row.target_host,
        target_port: row.target_port as u16,
        tls_mode: row.tls_mode,
        status: row.status,
        limits,
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/routes",
    responses((status = 200, description = "List routes", body = Vec<Route>)),
    tag = "routes"
)]
async fn list_routes(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
) -> Result<Response, ApiError> {
    require_permission(&user, Permission::RoutesRead)?;
    let rows = state.db.list_routes_detail().await.map_err(internal)?;
    let routes: Vec<Route> = rows.into_iter().map(route_response).collect();
    Ok(Json(routes).into_response())
}

#[utoipa::path(
    get,
    path = "/api/v1/routes/{id}",
    params(("id" = String, Path, description = "Route id")),
    responses(
        (status = 200, description = "Route detail", body = Route),
        (status = 404, description = "Route not found")
    ),
    tag = "routes"
)]
async fn get_route(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    require_permission(&user, Permission::RoutesRead)?;
    let row = state
        .db
        .get_route(&id)
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::not_found("ROUTE_NOT_FOUND", "route does not exist"))?;
    Ok(Json(route_response(row)).into_response())
}

#[utoipa::path(
    post,
    path = "/api/v1/routes",
    request_body = CreateRouteRequest,
    responses(
        (status = 201, description = "Route created", body = Route),
        (status = 404, description = "Node not found"),
        (status = 409, description = "Duplicate name/listen/hostname")
    ),
    tag = "routes"
)]
async fn create_route(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Json(body): Json<CreateRouteRequest>,
) -> Result<Response, ApiError> {
    require_permission(&user, Permission::RoutesWrite)?;
    let input = normalize(
        body.name,
        body.node_id,
        body.route_type,
        body.enabled,
        body.listen_host,
        body.listen_port,
        body.hostname,
        body.target_host,
        body.target_port,
        body.tls_mode,
        body.limits,
    )?;
    check_target(&input.target_host, state.allow_unsafe_targets)?;
    check_conflicts(&state.db, &input, None).await?;

    let id = Uuid::new_v4().to_string();
    let ts = now_rfc3339();
    let limits_json = input
        .limits
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(internal)?;
    state
        .db
        .create_route(
            &id,
            &input.name,
            &input.node_id,
            route_type_str(input.route_type),
            input.enabled,
            input.listen_host.as_deref(),
            input.listen_port.map(i64::from),
            input.hostname.as_deref(),
            &input.target_host,
            i64::from(input.target_port),
            tls_mode_str(input.tls_mode),
            limits_json.as_deref(),
            &ts,
        )
        .await
        .map_err(|e| map_db_error(e, "route"))?;

    // §28：路由变更使受影响 Node 的 config_version += 1，并推快照给在线 Agent。
    bump_and_push(&state, &input.node_id).await;

    let route = state
        .db
        .get_route(&id)
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::internal("route not found after create"))?;
    write_audit(
        &state,
        Some(&user.id),
        "route.create",
        "route",
        &id,
        Some(json!({ "name": input.name })),
    )
    .await?;
    state.events.publish(
        ROUTE_CREATED,
        json!({ "route_id": id, "name": input.name, "node_id": input.node_id }),
    );
    state
        .events
        .publish(CONFIG_UPDATED, json!({ "node_id": input.node_id }));
    Ok((StatusCode::CREATED, Json(route_response(route))).into_response())
}

#[utoipa::path(
    patch,
    path = "/api/v1/routes/{id}",
    params(("id" = String, Path, description = "Route id")),
    request_body = UpdateRouteRequest,
    responses(
        (status = 200, description = "Route updated", body = Route),
        (status = 404, description = "Route not found")
    ),
    tag = "routes"
)]
async fn update_route(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Path(id): Path<String>,
    Json(body): Json<UpdateRouteRequest>,
) -> Result<Response, ApiError> {
    require_permission(&user, Permission::RoutesWrite)?;
    let existing = state
        .db
        .get_route(&id)
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::not_found("ROUTE_NOT_FOUND", "route does not exist"))?;

    let existing_type = parse_route_type(&existing.route_type).unwrap_or(RouteType::Tcp);
    let route_type = body.route_type.unwrap_or(existing_type);

    // 按新 type 合并 listen/hostname（type 切换时丢弃旧 type 专属字段）。
    let (listen_host, listen_port, hostname) = match route_type {
        RouteType::Tcp | RouteType::Udp => (
            body.listen_host.or_else(|| existing.listen_host.clone()),
            body.listen_port
                .or_else(|| existing.listen_port.map(|p| p as u16)),
            None,
        ),
        RouteType::Http | RouteType::Https => (
            None,
            None,
            body.hostname.or_else(|| existing.hostname.clone()),
        ),
    };

    let tls_mode = body
        .tls_mode
        .or_else(|| parse_tls_mode(existing.tls_mode.as_deref()));
    let limits = match body.limits {
        Some(l) => Some(l),
        None => existing
            .limits
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok()),
    };

    let input = normalize(
        body.name.unwrap_or(existing.name),
        body.node_id.unwrap_or_else(|| existing.node_id.clone()),
        route_type,
        body.enabled.unwrap_or(existing.enabled),
        listen_host,
        listen_port,
        hostname,
        body.target_host.unwrap_or(existing.target_host),
        body.target_port.unwrap_or(existing.target_port as u16),
        tls_mode,
        limits,
    )?;
    check_target(&input.target_host, state.allow_unsafe_targets)?;
    check_conflicts(&state.db, &input, Some(&id)).await?;

    let ts = now_rfc3339();
    let limits_json = input
        .limits
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(internal)?;
    state
        .db
        .update_route(
            &id,
            &input.name,
            &input.node_id,
            route_type_str(input.route_type),
            input.enabled,
            input.listen_host.as_deref(),
            input.listen_port.map(i64::from),
            input.hostname.as_deref(),
            &input.target_host,
            i64::from(input.target_port),
            tls_mode_str(input.tls_mode),
            limits_json.as_deref(),
            &ts,
        )
        .await
        .map_err(|e| map_db_error(e, "route"))?;

    // §28：受影响 Node 版本 +1 并推快照；换 node 时新旧 node 都要重算。
    bump_and_push(&state, &input.node_id).await;
    if existing.node_id != input.node_id {
        bump_and_push(&state, &existing.node_id).await;
    }

    let route = state
        .db
        .get_route(&id)
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::internal("route not found after update"))?;
    write_audit(
        &state,
        Some(&user.id),
        "route.update",
        "route",
        &id,
        Some(json!({ "name": input.name })),
    )
    .await?;
    state.events.publish(
        ROUTE_UPDATED,
        json!({ "route_id": id, "name": input.name, "node_id": input.node_id }),
    );
    state
        .events
        .publish(CONFIG_UPDATED, json!({ "node_id": input.node_id }));
    Ok(Json(route_response(route)).into_response())
}

#[utoipa::path(
    delete,
    path = "/api/v1/routes/{id}",
    params(("id" = String, Path, description = "Route id")),
    responses(
        (status = 204, description = "Route deleted"),
        (status = 404, description = "Route not found")
    ),
    tag = "routes"
)]
async fn delete_route(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    require_permission(&user, Permission::RoutesWrite)?;
    let existing = state
        .db
        .get_route(&id)
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::not_found("ROUTE_NOT_FOUND", "route does not exist"))?;
    state.db.delete_route(&id).await.map_err(internal)?;
    bump_and_push(&state, &existing.node_id).await;
    write_audit(&state, Some(&user.id), "route.delete", "route", &id, None).await?;
    state.events.publish(
        ROUTE_DELETED,
        json!({ "route_id": id, "name": existing.name, "node_id": existing.node_id }),
    );
    state
        .events
        .publish(CONFIG_UPDATED, json!({ "node_id": existing.node_id }));
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[utoipa::path(
    post,
    path = "/api/v1/routes/{id}/enable",
    params(("id" = String, Path, description = "Route id")),
    responses(
        (status = 200, description = "Route enabled", body = Route),
        (status = 404, description = "Route not found")
    ),
    tag = "routes"
)]
async fn enable_route(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    require_permission(&user, Permission::RoutesWrite)?;
    set_enabled(&state, &user.id, id, true, "route.enable").await
}

#[utoipa::path(
    post,
    path = "/api/v1/routes/{id}/disable",
    params(("id" = String, Path, description = "Route id")),
    responses(
        (status = 200, description = "Route disabled", body = Route),
        (status = 404, description = "Route not found")
    ),
    tag = "routes"
)]
async fn disable_route(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    require_permission(&user, Permission::RoutesWrite)?;
    set_enabled(&state, &user.id, id, false, "route.disable").await
}

async fn set_enabled(
    state: &AppState,
    user_id: &str,
    id: String,
    enabled: bool,
    action: &str,
) -> Result<Response, ApiError> {
    let existing = state
        .db
        .get_route(&id)
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::not_found("ROUTE_NOT_FOUND", "route does not exist"))?;
    let ts = now_rfc3339();
    state
        .db
        .set_route_enabled(&id, enabled, &ts)
        .await
        .map_err(internal)?;
    bump_and_push(&state, &existing.node_id).await;
    write_audit(
        state,
        Some(user_id),
        action,
        "route",
        &id,
        Some(json!({ "enabled": enabled })),
    )
    .await?;
    state.events.publish(
        ROUTE_UPDATED,
        json!({ "route_id": id, "name": existing.name, "node_id": existing.node_id }),
    );
    state
        .events
        .publish(CONFIG_UPDATED, json!({ "node_id": existing.node_id }));
    let route = state
        .db
        .get_route(&id)
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::internal("route not found after update"))?;
    Ok(Json(route_response(route)).into_response())
}
