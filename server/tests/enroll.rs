//! 集成测试（T-22）：Node 创建签发 bootstrap token、`/enroll`、运行时凭据签发/吊销。
//!
//! 验收：token 明文仅创建时返回一次、DB 只存 SHA-256；revoke 后 Agent 无法认证；
//! bootstrap token 可一次性 enroll，成功后作废。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::{to_bytes, Body};
use axum::http::{header, HeaderMap, Request, StatusCode};
use tower::ServiceExt;

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tunnel_auth::{hash_password, hash_token};
use tunnel_core::auth::{authenticate, AuthDecision};
use tunnel_db::Db;
use tunnel_protocol::AuthPayload;
use tunnel_server::api::AppState;

const USER_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const NOW: &str = "2026-08-27T00:00:00Z";

async fn seeded_db() -> Db {
    let db = Db::connect_memory().await.unwrap();
    db.migrate().await.unwrap();

    tunnel_db::sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, disabled, created_at, updated_at) \
         VALUES (?, 'admin', 'admin@example.com', ?, 0, ?, ?)",
    )
    .bind(USER_ID)
    .bind(hash_password("hunter2").unwrap())
    .bind(NOW)
    .bind(NOW)
    .execute(db.pool())
    .await
    .unwrap();

    // admin 角色由迁移（0003_seed_roles）种入，按 name 复用。
    let role_id: String =
        tunnel_db::sqlx::query_scalar("SELECT id FROM roles WHERE name = 'admin'")
            .fetch_one(db.pool())
            .await
            .unwrap();

    tunnel_db::sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)")
        .bind(USER_ID)
        .bind(&role_id)
        .execute(db.pool())
        .await
        .unwrap();

    db
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

async fn login_token(app: &axum::Router) -> String {
    let (status, json, _) = send(
        app,
        json_req(
            "POST",
            "/auth/login",
            r#"{"username":"admin","password":"hunter2"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login should succeed");
    json["access_token"].as_str().unwrap().to_string()
}

async fn create_node(app: &axum::Router, token: &str, name: &str) -> serde_json::Value {
    let (status, json, _) = send(
        app,
        bearer_req(
            "POST",
            "/api/v1/nodes",
            token,
            &format!(r#"{{"name":"{name}","description":"test node"}}"#),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create node failed: {json}");
    json
}

fn now() -> OffsetDateTime {
    OffsetDateTime::parse("2026-08-27T12:00:00Z", &Rfc3339).unwrap()
}

fn auth_payload(token: &str) -> AuthPayload {
    AuthPayload {
        node_id: None,
        credential: Some(token.to_string()),
    }
}

#[tokio::test]
async fn node_create_returns_bootstrap_token_stored_as_hash() {
    let db = seeded_db().await;
    let app = app(db.clone());
    let token = login_token(&app).await;

    let node = create_node(&app, &token, "home").await;
    let bt = node["bootstrap_token"].as_str().unwrap();
    assert_eq!(bt.len(), 64, "bootstrap token must be 32-byte hex");

    // DB 只存 SHA-256，不存明文。
    let hash: String = tunnel_db::sqlx::query_scalar(
        "SELECT secret_hash FROM credentials WHERE type = 'bootstrap'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(hash, hash_token(bt));
    assert_ne!(hash, bt);

    // 明文 token 不随列表/详情再泄露。
    let (status, json, _) = send(&app, bearer_req("GET", "/api/v1/nodes", &token, "")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!json.to_string().contains(bt));
}

#[tokio::test]
async fn credential_create_shows_token_once_and_revoke_blocks_auth() {
    let db = seeded_db().await;
    let app = app(db.clone());
    let admin = login_token(&app).await;
    let node = create_node(&app, &admin, "home").await;
    let node_id = node["node"]["id"].as_str().unwrap();

    // 签发运行时凭据。
    let (status, json, _) = send(
        &app,
        bearer_req(
            "POST",
            &format!("/api/v1/nodes/{node_id}/credentials"),
            &admin,
            r#"{"type":"token"}"#,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create credential failed: {json}"
    );
    let cred_id = json["id"].as_str().unwrap().to_string();
    let runtime = json["token"].as_str().unwrap().to_string();
    assert_eq!(runtime.len(), 64);

    // DB 存 hash。
    let hash: String =
        tunnel_db::sqlx::query_scalar("SELECT secret_hash FROM credentials WHERE id = ?")
            .bind(&cred_id)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(hash, hash_token(&runtime));

    // 运行时 token 能通过数据面认证。
    assert!(matches!(
        authenticate(&db, &auth_payload(&runtime), now()).await,
        AuthDecision::Success(_)
    ));

    // 吊销 → 之后无法认证。
    let (status, _, _) = send(
        &app,
        bearer_req(
            "POST",
            &format!("/api/v1/nodes/{node_id}/credentials/{cred_id}/revoke"),
            &admin,
            "",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(matches!(
        authenticate(&db, &auth_payload(&runtime), now()).await,
        AuthDecision::Failure {
            code: "AUTH_FAILED",
            ..
        }
    ));
}

#[tokio::test]
async fn enroll_exchanges_bootstrap_for_runtime_token_once() {
    let db = seeded_db().await;
    let app = app(db.clone());
    let admin = login_token(&app).await;
    let node = create_node(&app, &admin, "home").await;
    let node_id = node["node"]["id"].as_str().unwrap().to_string();
    let bt = node["bootstrap_token"].as_str().unwrap().to_string();

    let body = format!(
        r#"{{"bootstrap_token":"{bt}","node_name":"home","hostname":"nas","platform":"linux","architecture":"x86_64","agent_version":"0.1.0"}}"#
    );

    let (status, json, _) = send(&app, json_req("POST", "/enroll", &body)).await;
    assert_eq!(status, StatusCode::OK, "enroll failed: {json}");
    assert_eq!(json["node_id"], node_id.as_str());
    let runtime = json["credential"].as_str().unwrap().to_string();
    assert_eq!(runtime.len(), 64);

    // Agent 元数据已合并进 node。
    let hostname: Option<String> =
        tunnel_db::sqlx::query_scalar("SELECT hostname FROM nodes WHERE id = ?")
            .bind(&node_id)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(hostname.as_deref(), Some("nas"));

    // 运行时 token 可认证。
    assert!(matches!(
        authenticate(&db, &auth_payload(&runtime), now()).await,
        AuthDecision::Success(_)
    ));

    // bootstrap token 已作废 → 再次 enroll 401。
    let (status, json, _) = send(&app, json_req("POST", "/enroll", &body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"]["code"], "UNAUTHORIZED");
}

#[tokio::test]
async fn enroll_rejects_unknown_bootstrap_token() {
    let db = seeded_db().await;
    let app = app(db.clone());
    let (status, json, _) = send(
        &app,
        json_req("POST", "/enroll", r#"{"bootstrap_token":"deadbeef"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"]["code"], "UNAUTHORIZED");
}

#[tokio::test]
async fn enroll_rejects_node_name_mismatch() {
    let db = seeded_db().await;
    let app = app(db.clone());
    let admin = login_token(&app).await;
    let node = create_node(&app, &admin, "home").await;
    let bt = node["bootstrap_token"].as_str().unwrap();

    let body = format!(r#"{{"bootstrap_token":"{bt}","node_name":"other"}}"#);
    let (status, json, _) = send(&app, json_req("POST", "/enroll", &body)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json["error"]["code"], "NODE_NAME_MISMATCH");
}
