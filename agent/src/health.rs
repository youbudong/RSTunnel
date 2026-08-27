//! Agent 本地存活探针（T-39/§97）：`GET /health` 返回 `{ "status": "ok" }`。
//!
//! 与 Server 的 `/ready` 不同，Agent 探针仅表示进程存活（liveness），不判定隧道是否在线；
//! 供编排器/`systemctl` 探活，监听地址来自 `[health].bind`（默认 `127.0.0.1:9090`）。

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;

/// 存活探针路由（无状态，返回 `Router<()>`）。
pub fn router() -> Router {
    Router::new().route("/health", get(health))
}

async fn health() -> Response {
    (StatusCode::OK, Json(json!({ "status": "ok" }))).into_response()
}
