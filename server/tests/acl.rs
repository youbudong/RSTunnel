//! 集成测试（T-34）：`/api/v1/acl-rules` 管理面——CRUD、校验、RBAC（viewer 写 403）。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use tunnel_auth::hash_password;
use tunnel_db::Db;
use tunnel_server::api::AppState;

const NOW: &str = "2026-08-27T00:00:00Z";
const NODE_ID: &str = "22222222-2222-4222-8222-222222222222";
const ROUTE_ID: &str = "33333333-3333-4333-8333-333333333333";

async fn seeded_db() -> Db {
    let db = Db::connect_memory().await.unwrap();
    db.migrate().await.unwrap();

    // roles 由迁移（0003_seed_roles）种入，按 name 复用。
    insert_user(&db, "user-admin", "admin", "adminpass", "admin").await;
    insert_user(&db, "user-viewer", "viewer", "view-pass", "viewer").await;

    // 一个 node + 一个 route，供 route 作用域 ACL 规则引用。
    tunnel_db::sqlx::query(
        "INSERT INTO nodes (id, name, config_version, created_at, updated_at) VALUES (?, ?, 0, ?, ?)",
    )
    .bind(NODE_ID)
    .bind("node-a")
    .bind(NOW)
    .bind(NOW)
    .execute(db.pool())
    .await
    .unwrap();
    tunnel_db::sqlx::query(
        "INSERT INTO routes (id, name, node_id, type, enabled, listen_host, listen_port, \
         target_host, target_port, status, created_at, updated_at) \
         VALUES (?, 'ssh', ?, 'tcp', 1, '127.0.0.1', 2222, '192.168.1.100', 22, 'active', ?, ?)",
    )
    .bind(ROUTE_ID)
    .bind(NODE_ID)
    .bind(NOW)
    .bind(NOW)
    .execute(db.pool())
    .await
    .unwrap();

    db
}

async fn insert_user(db: &Db, id: &str, username: &str, password: &str, role_name: &str) {
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

    // 角色由迁移（0003_seed_roles）种入，按 name 取 id。
    let role_id: String = tunnel_db::sqlx::query_scalar("SELECT id FROM roles WHERE name = ?")
        .bind(role_name)
        .fetch_one(db.pool())
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
        Request::builder()
            .method("POST")
            .uri("/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(
                r#"{{"username":"{username}","password":"{password}"}}"#
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login {username} failed: {json}");
    json["access_token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn admin_can_create_list_and_delete_rules() {
    let db = seeded_db().await;
    let app = app(db.clone());
    let token = login(&app, "admin", "adminpass").await;

    // 创建 route 作用域 allow 规则。
    let body = format!(
        r#"{{"route_id":"{ROUTE_ID}","action":"allow","source_cidr":"10.0.0.0/8","source_port":8080}}"#
    );
    let (status, json) = send(&app, bearer_req("POST", "/api/v1/acl-rules", &token, &body)).await;
    assert_eq!(status, StatusCode::CREATED, "create acl rule: {json}");
    let id = json["id"].as_str().unwrap().to_string();
    assert_eq!(json["action"], "allow");
    assert_eq!(json["route_id"], ROUTE_ID);
    assert_eq!(json["source_cidr"], "10.0.0.0/8");
    assert_eq!(json["source_port"], 8080);

    // 列表含新规则。
    let (status, list) = send(&app, bearer_req("GET", "/api/v1/acl-rules", &token, "")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(list.as_array().unwrap().iter().any(|r| r["id"] == id));

    // 删除 → 204 → 列表不再包含。
    let (status, _) = send(
        &app,
        bearer_req("POST", &format!("/api/v1/acl-rules/{id}"), &token, ""),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, list) = send(&app, bearer_req("GET", "/api/v1/acl-rules", &token, "")).await;
    assert!(!list.as_array().unwrap().iter().any(|r| r["id"] == id));
}

#[tokio::test]
async fn invalid_rules_are_rejected() {
    let db = seeded_db().await;
    let app = app(db.clone());
    let token = login(&app, "admin", "adminpass").await;

    // 非法 action。
    let (status, json) = send(
        &app,
        bearer_req("POST", "/api/v1/acl-rules", &token, r#"{"action":"maybe"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json["error"]["code"], "INVALID_ACTION");

    // 非法 source_cidr。
    let (status, json) = send(
        &app,
        bearer_req(
            "POST",
            "/api/v1/acl-rules",
            &token,
            r#"{"action":"allow","source_cidr":"999.1.2.3/99"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json["error"]["code"], "INVALID_CIDR");

    // route_id 不存在。
    let (status, json) = send(
        &app,
        bearer_req(
            "POST",
            "/api/v1/acl-rules",
            &token,
            r#"{"route_id":"99999999-9999-4999-8999-999999999999","action":"allow"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(json["error"]["code"], "ROUTE_NOT_FOUND");
}

#[tokio::test]
async fn viewer_can_read_but_not_write() {
    let db = seeded_db().await;
    let app = app(db.clone());
    let token = login(&app, "viewer", "view-pass").await;

    // 读放行。
    let (status, _) = send(&app, bearer_req("GET", "/api/v1/acl-rules", &token, "")).await;
    assert_eq!(status, StatusCode::OK);
    // 写 403。
    let (status, json) = send(
        &app,
        bearer_req("POST", "/api/v1/acl-rules", &token, r#"{"action":"allow"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(json["error"]["code"], "FORBIDDEN");
}
