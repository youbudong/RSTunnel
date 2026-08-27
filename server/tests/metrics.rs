//! 集成测试（T-38）：`GET /metrics` 暴露 Prometheus 文本指标（设计文档 §38）。
//!
//! 覆盖验收：`curl 127.0.0.1:8080/metrics` 输出规范指标——`text/plain` 响应、
//! §38 全部指标名齐备、DB 派生的 `nodes_total` 反映实际计数。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use tunnel_db::Db;
use tunnel_server::api::AppState;

#[tokio::test]
async fn metrics_endpoint_returns_prometheus_text() {
    let db = Db::connect_memory().await.unwrap();
    db.migrate().await.unwrap();
    let app = tunnel_server::api::router(AppState::new(db));

    // 生产 main 在启动时 `register_all()`；测试同样先注册，保证 §38 指标全部出现。
    tunnel_metrics::register_all().unwrap();

    let req = Request::builder()
        .method("GET")
        .uri("/metrics")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.starts_with("text/plain"), "content-type: {ct}");

    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();

    for name in [
        "tunnel_nodes_online",
        "tunnel_nodes_total",
        "tunnel_sessions_active",
        "tunnel_streams_active",
        "tunnel_connections_total",
        "tunnel_connections_failed",
        "tunnel_bytes_received_total",
        "tunnel_bytes_sent_total",
        "tunnel_udp_packets_total",
        "tunnel_route_errors_total",
    ] {
        assert!(text.contains(name), "missing metric {name}\n{text}");
    }

    // 空库：nodes_total 应为 0（handler 每次抓取刷新 DB 派生计数）。
    assert!(text.contains("tunnel_nodes_total 0"), "nodes_total: {text}");
}
