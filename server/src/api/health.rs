//! 健康检查与就绪端点（T-39/§97/§98）：`/health`（存活）与 `/ready`（就绪）。
//!
//! `/health` 恒 200——进程在服务即存活；`/ready` 在 §98 四类组件（DB/配置/QUIC/HTTP）
//! 未全部就绪时返回 503，并对 DB 做一次实时 `SELECT 1` 探测。

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;

use super::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
}

async fn health() -> Response {
    (StatusCode::OK, Json(json!({ "status": "ok" }))).into_response()
}

async fn ready(State(state): State<AppState>) -> Response {
    // DB 实时探测（§98：database connected）——连接池可能在启动后失联。
    let db_ping = db_ping(&state).await;
    let database = db_ping && state.readiness.db_ready();
    let configuration = state.readiness.config_ready();
    let quic = state.readiness.quic_ready();
    let http = state.readiness.http_ready();
    let all = database && configuration && quic && http;

    let status = if all {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let body = json!({
        "status": if all { "ready" } else { "not_ready" },
        "components": {
            "database": database,
            "configuration": configuration,
            "quic": quic,
            "http": http,
        },
    });
    (status, Json(body)).into_response()
}

async fn db_ping(state: &AppState) -> bool {
    tunnel_db::sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(state.db.pool())
        .await
        .map(|n| n == 1)
        .unwrap_or(false)
}
