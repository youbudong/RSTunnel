//! Prometheus 指标端点（T-38/§38）：`GET /metrics`，暴露 default registry 的文本格式。
//!
//! 与 `/health`/`/ready` 一样挂在 internal 回环端口，无需认证。每次抓取时刷新
//! 反映 DB 状态的高水位指标（`tunnel_nodes_total`）；连接/字节/包等增量计数在数据面
//! 实时累加，无需在此刷新。

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

use super::{internal, ApiError, AppState};

pub fn router() -> Router<AppState> {
    Router::new().route("/metrics", get(metrics))
}

async fn metrics(State(state): State<AppState>) -> Result<Response, ApiError> {
    // 每次抓取刷新 DB 派生的总量指标（nodes_total）。在线数/字节/连接等由数据面实时维护。
    let total = state.db.count_nodes().await.map_err(internal)?;
    if let Some(g) = tunnel_metrics::nodes_total() {
        g.set(total as f64);
    }
    Ok(render_metrics())
}

fn render_metrics() -> Response {
    let body = tunnel_metrics::render();
    let mut resp = body.into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    resp
}
