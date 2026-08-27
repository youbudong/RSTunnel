//! 集成测试（T-33）：RBAC——viewer 只读（写 403）、admin 全通、operator 可写 nodes/routes。
//!
//! 覆盖默认角色（§31/§161）：`admin` 全权；`operator` = nodes/routes 读写；`viewer` = 全部只读。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use tunnel_auth::hash_password;
use tunnel_db::Db;
use tunnel_server::api::AppState;

const NOW: &str = "2026-08-27T00:00:00Z";
const ROLE_ADMIN: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa01";
const ROLE_OPERATOR: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa02";
const ROLE_VIEWER: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa03";

async fn seeded_db() -> Db {
    let db = Db::connect_memory().await.unwrap();
    db.migrate().await.unwrap();

    for (id, name) in [
        (ROLE_ADMIN, "admin"),
        (ROLE_OPERATOR, "operator"),
        (ROLE_VIEWER, "viewer"),
    ] {
        tunnel_db::sqlx::query("INSERT INTO roles (id, name) VALUES (?, ?)")
            .bind(id)
            .bind(name)
            .execute(db.pool())
            .await
            .unwrap();
    }

    insert_user(&db, "user-admin", "admin", "adminpass", ROLE_ADMIN).await;
    insert_user(&db, "user-operator", "operator", "op-pass", ROLE_OPERATOR).await;
    insert_user(&db, "user-viewer", "viewer", "view-pass", ROLE_VIEWER).await;

    db
}

async fn insert_user(db: &Db, id: &str, username: &str, password: &str, role_id: &str) {
    tunnel_db::sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, disabled, created_at, updated_at) \
         VALUES (?, ?, NULL, ?, 0, ?, ?)",
    )
    .bind(id)
    .bind(username)
    .bind(hash_password(password).unwrap())
    .bind(NOW)
    .bind(NOW)
    .execute(db.pool())
    .await
    .unwrap();

    tunnel_db::sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)")
        .bind(id)
        .bind(role_id)
        .execute(db.pool())
        .await
        .unwrap();
}

fn app(db: Db) -> axum::Router {
    tunnel_server::api::router(AppState::new(db))
}

fn json_req(method: &str, uri: &str, body: &str) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if !body.is_empty() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn bearer_req(method: &str, uri: &str, token: &str, body: &str) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    if !body.is_empty() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    b.body(Body::from(body.to_string())).unwrap()
}

async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

async fn login(app: &axum::Router, username: &str, password: &str) -> String {
    let (status, json) = send(
        app,
        json_req(
            "POST",
            "/auth/login",
            &format!(r#"{{"username":"{username}","password":"{password}"}}"#),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login {username} failed: {json}");
    json["access_token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn viewer_is_read_only() {
    let db = seeded_db().await;
    let app = app(db.clone());
    let token = login(&app, "viewer", "view-pass").await;

    // 读：nodes/routes 均放行。
    let (status, _) = send(&app, bearer_req("GET", "/api/v1/nodes", &token, "")).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(&app, bearer_req("GET", "/api/v1/routes", &token, "")).await;
    assert_eq!(status, StatusCode::OK);

    // 写：nodes/routes 均 403（权限校验先于参数校验，故可用任意 body）。
    let (status, json) = send(
        &app,
        bearer_req("POST", "/api/v1/nodes", &token, r#"{"name":"x"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(json["error"]["code"], "FORBIDDEN");

    // 注意：body 必须是合法 CreateRouteRequest（否则 Json 提取器在 handler 前返回 422，
    // 而非触发权限校验）。合法 body 会先过 require_permission → 403。
    let route_body = r#"{"name":"x","node_id":"node-x","type":"http","target_host":"127.0.0.1","target_port":8080}"#;
    let (status, json) = send(
        &app,
        bearer_req("POST", "/api/v1/routes", &token, route_body),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(json["error"]["code"], "FORBIDDEN");
}

#[tokio::test]
async fn admin_full_and_operator_write_nodes() {
    let db = seeded_db().await;
    let app = app(db.clone());

    // admin：写 nodes 201（全权）。
    let admin = login(&app, "admin", "adminpass").await;
    let (status, json) = send(
        &app,
        bearer_req("POST", "/api/v1/nodes", &admin, r#"{"name":"home"}"#),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "admin create node failed: {json}"
    );

    // operator：读 + 写 nodes 均放行（§161）。
    let operator = login(&app, "operator", "op-pass").await;
    let (status, _) = send(&app, bearer_req("GET", "/api/v1/nodes", &operator, "")).await;
    assert_eq!(status, StatusCode::OK);
    let (status, json) = send(
        &app,
        bearer_req("POST", "/api/v1/nodes", &operator, r#"{"name":"nas"}"#),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "operator create node failed: {json}"
    );
}
