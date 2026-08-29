//! 集成测试（T-20 首次引导）：`users` 表为空时，`/api/v1/setup` 允许创建初始管理员
//! （admin 角色）并签发会话；创建后自锁（409）。迁移 0003 种入的 admin 角色被复用。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;

use tunnel_db::Db;
use tunnel_server::api::AppState;

async fn migrated_db() -> Db {
    let db = Db::connect_memory().await.unwrap();
    db.migrate().await.unwrap();
    db
}

fn app(db: Db) -> axum::Router {
    tunnel_server::api::router(AppState::new(db))
}

async fn get(app: &axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, value)
}

async fn post_json(
    app: &axum::Router,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, value)
}

#[tokio::test]
async fn setup_status_reports_uninitialized_on_empty_db() {
    let app = app(migrated_db().await);
    let (status, body) = get(&app, "/api/v1/setup").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["initialized"].as_bool(), Some(false));
}

#[tokio::test]
async fn setup_creates_admin_and_returns_session() {
    let app = app(migrated_db().await);
    let (status, body) = post_json(
        &app,
        "/api/v1/setup",
        json!({
            "username": "admin",
            "password": "correct-horse-battery",
            "email": "admin@example.com"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got: {body}");
    assert_eq!(body["user"]["username"].as_str(), Some("admin"));
    assert_eq!(body["user"]["role"].as_str(), Some("admin"));
    assert!(body["access_token"].is_string(), "got: {body}");

    // 创建后 setup 状态转为已初始化。
    let (status, body) = get(&app, "/api/v1/setup").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["initialized"].as_bool(), Some(true));
}

#[tokio::test]
async fn setup_then_login_succeeds() {
    let app = app(migrated_db().await);
    let (status, _) = post_json(
        &app,
        "/api/v1/setup",
        json!({ "username": "root", "password": "supersecret" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = post_json(
        &app,
        "/auth/login",
        json!({ "username": "root", "password": "supersecret" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got: {body}");
    assert_eq!(body["user"]["role"].as_str(), Some("admin"));
}

#[tokio::test]
async fn setup_rejected_after_initialized() {
    let app = app(migrated_db().await);
    let (status, _) = post_json(
        &app,
        "/api/v1/setup",
        json!({ "username": "admin", "password": "supersecret1" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = post_json(
        &app,
        "/api/v1/setup",
        json!({ "username": "second", "password": "supersecret2" }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "got: {body}");
    assert_eq!(body["error"]["code"].as_str(), Some("SETUP_ALREADY_DONE"));
}

#[tokio::test]
async fn setup_rejects_weak_password() {
    let app = app(migrated_db().await);
    let (status, body) = post_json(
        &app,
        "/api/v1/setup",
        json!({ "username": "admin", "password": "short" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "got: {body}");
    assert_eq!(body["error"]["code"].as_str(), Some("WEAK_PASSWORD"));
}
