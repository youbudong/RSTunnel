//! 集成测试（T-36）：审计完整性——登录/登出/登录失败写 audit_logs；审计查询 API 与 RBAC。
//!
//! 覆盖设计文档 §40（login/logout/login.failed 可追溯）与 api.md §8/§12
//! （`GET /api/v1/audit-logs` 需 `audit.read` 权限：admin/viewer 可读，operator 403）。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::{to_bytes, Body};
use axum::http::{header, HeaderMap, Request, StatusCode};
use tower::ServiceExt;

use tunnel_auth::hash_password;
use tunnel_db::Db;
use tunnel_server::api::AppState;

const NOW: &str = "2026-08-27T00:00:00Z";
const USER_ADMIN: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa11";
const USER_OPERATOR: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa12";
const USER_VIEWER: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa13";

async fn seeded_db() -> Db {
    let db = Db::connect_memory().await.unwrap();
    db.migrate().await.unwrap();

    // roles（admin/operator/viewer）由迁移（0003_seed_roles）种入，按 name 复用。
    insert_user(&db, USER_ADMIN, "admin", "adminpass", "admin").await;
    insert_user(&db, USER_OPERATOR, "operator", "op-pass", "operator").await;
    insert_user(&db, USER_VIEWER, "viewer", "view-pass", "viewer").await;

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

fn json_req(method: &str, uri: &str, body: &str) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if !body.is_empty() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn bearer_req(method: &str, uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn cookie_req(method: &str, uri: &str, sid: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::COOKIE, format!("sid={sid}"))
        .body(Body::empty())
        .unwrap()
}

async fn send(
    app: &axum::Router,
    req: Request<Body>,
) -> (StatusCode, serde_json::Value, HeaderMap) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json, headers)
}

fn session_id_from_set_cookie(headers: &HeaderMap) -> String {
    let cookie = headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
    cookie
        .split(';')
        .next()
        .unwrap()
        .trim()
        .strip_prefix("sid=")
        .unwrap()
        .to_string()
}

/// 登录并返回 (access_token, session_id)。
async fn login(app: &axum::Router, username: &str, password: &str) -> (String, String) {
    let (status, json, headers) = send(
        app,
        json_req(
            "POST",
            "/auth/login",
            &format!(r#"{{"username":"{username}","password":"{password}"}}"#),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login {username} failed: {json}");
    let token = json["access_token"].as_str().unwrap().to_string();
    let sid = session_id_from_set_cookie(&headers);
    (token, sid)
}

/// 从审计查询响应抽取全部 action 码。
fn audit_actions(json: &serde_json::Value) -> Vec<String> {
    json.as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["action"].as_str().map(str::to_string))
        .collect()
}

#[tokio::test]
async fn login_logout_and_failure_write_audit_entries() {
    let db = seeded_db().await;
    let app = app(db.clone());

    // 登录成功 → login。
    let (_, sid) = login(&app, "admin", "adminpass").await;

    // 登录失败 → login.failed。
    let (status, _, _) = send(
        &app,
        json_req(
            "POST",
            "/auth/login",
            r#"{"username":"admin","password":"wrong"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 登出 → logout（登出会吊销会话及其 access token）。
    let (status, _, _) = send(&app, cookie_req("POST", "/auth/logout", &sid)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // 重新登录拿可用 token 查询审计。
    let (admin_token, _) = login(&app, "admin", "adminpass").await;
    let (status, json, _) = send(&app, bearer_req("GET", "/api/v1/audit-logs", &admin_token)).await;
    assert_eq!(status, StatusCode::OK);

    let actions = audit_actions(&json);
    assert!(
        actions.iter().any(|a| a == "login"),
        "missing login in {json}"
    );
    assert!(
        actions.iter().any(|a| a == "logout"),
        "missing logout in {json}"
    );
    assert!(
        actions.iter().any(|a| a == "login.failed"),
        "missing login.failed in {json}"
    );

    // 登录条目指向 admin 用户（可追溯）。
    let login_entry = json
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["action"] == "login")
        .unwrap();
    assert_eq!(login_entry["user_id"], USER_ADMIN);
    assert_eq!(login_entry["resource_type"], "user");
}

#[tokio::test]
async fn audit_logs_enforce_audit_read_permission() {
    let db = seeded_db().await;
    let app = app(db.clone());

    // 未认证 → 401。
    let (status, _, _) = send(&app, json_req("GET", "/api/v1/audit-logs", "")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // operator：无 audit.read → 403。
    let (operator_token, _) = login(&app, "operator", "op-pass").await;
    let (status, json, _) = send(
        &app,
        bearer_req("GET", "/api/v1/audit-logs", &operator_token),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(json["error"]["code"], "FORBIDDEN");

    // viewer：只读，含 audit.read → 200。
    let (viewer_token, _) = login(&app, "viewer", "view-pass").await;
    let (status, _, _) = send(&app, bearer_req("GET", "/api/v1/audit-logs", &viewer_token)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn audit_logs_filter_by_action() {
    let db = seeded_db().await;
    let app = app(db.clone());

    let (admin_token, _) = login(&app, "admin", "adminpass").await;
    // 制造一条 login.failed。
    let _ = send(
        &app,
        json_req(
            "POST",
            "/auth/login",
            r#"{"username":"admin","password":"nope"}"#,
        ),
    )
    .await;

    // 按 action=login.failed 过滤，只返回该类条目。
    let (status, json, _) = send(
        &app,
        bearer_req(
            "GET",
            "/api/v1/audit-logs?action=login.failed",
            &admin_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let actions = audit_actions(&json);
    assert!(!actions.is_empty());
    assert!(actions.iter().all(|a| a == "login.failed"));
}
