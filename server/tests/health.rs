//! 集成测试（T-39）：`/health` 恒 200；`/ready` 在 §98 四类组件就绪时 200、否则 503。
//!
//! §98 就绪条件：database connected / configuration loaded / QUIC listener ready /
//! HTTP listener ready。测试通过注入不同 [`Readiness`] 状态验证判定逻辑。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use tunnel_db::Db;
use tunnel_server::api::AppState;
use tunnel_server::readiness::Readiness;

async fn send(app: &axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

async fn migrated_db() -> Db {
    let db = Db::connect_memory().await.unwrap();
    db.migrate().await.unwrap();
    db
}

#[tokio::test]
async fn health_always_ok() {
    let app = tunnel_server::api::router(AppState::new(migrated_db().await));
    let (status, json) = send(&app, "/health").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "ok");
}

#[tokio::test]
async fn ready_returns_ok_when_all_components_ready() {
    // AppState::new 默认全部就绪。
    let app = tunnel_server::api::router(AppState::new(migrated_db().await));
    let (status, json) = send(&app, "/ready").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "ready");
    assert_eq!(json["components"]["database"], true);
    assert_eq!(json["components"]["configuration"], true);
    assert_eq!(json["components"]["quic"], true);
    assert_eq!(json["components"]["http"], true);
}

#[tokio::test]
async fn ready_returns_503_when_a_component_not_ready() {
    // 模拟启动中途：DB 尚未就绪（flag 未置位），其余就绪。
    let readiness = Arc::new(Readiness::new());
    readiness.mark_config();
    readiness.mark_quic();
    readiness.mark_http();

    let app =
        tunnel_server::api::router(AppState::new(migrated_db().await).with_readiness(readiness));
    let (status, json) = send(&app, "/ready").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json["status"], "not_ready");
    assert_eq!(json["components"]["database"], false);
    // 就绪组件仍为 true，便于定位瓶颈。
    assert_eq!(json["components"]["quic"], true);
    assert_eq!(json["components"]["http"], true);
}

#[tokio::test]
async fn ready_returns_503_when_quic_not_ready() {
    // 模拟 QUIC 尚未就绪（其余就绪，含 DB 实时探测）。
    let readiness = Arc::new(Readiness::new());
    readiness.mark_db();
    readiness.mark_config();
    readiness.mark_http();

    let app =
        tunnel_server::api::router(AppState::new(migrated_db().await).with_readiness(readiness));
    let (status, json) = send(&app, "/ready").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json["components"]["quic"], false);
    assert_eq!(json["components"]["database"], true);
}
